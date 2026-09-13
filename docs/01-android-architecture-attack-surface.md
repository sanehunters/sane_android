# Android Architecture as an Attack Surface

> This is the conceptual backbone of the checklist. Everything in `checklist/D01`–`D27` is a consequence
> of what is written here. If you only ever run the checklist you will find what the checklist knows
> about. If you understand this document you will find what it does not.
>
> Read it before your first engagement, and again the first time a target does something the checklist
> has no row for.

---

## The organising principle

Android's security model is two mechanisms welded together: a **per-application UID sandbox** enforced by
the kernel, and a **Binder IPC layer** that exists precisely so that sandboxed processes can still ask each
other for things. Everything else — permissions, app-ops, roles, SELinux domains, URI grants, PendingIntents,
key attestation — is scaffolding around that join.

AOSP describes three distinct access-control mechanisms, and the distinction between them is the single most
useful thing a tester can hold in their head:

| Mechanism | Enforced by | Enforced where | Can the app get it wrong? |
|---|---|---|---|
| **DAC** — UID/GID, file modes | Linux kernel | Every `open()`, `read()`, `write()` | No. It is not the app's decision. |
| **MAC** — SELinux domains, types, MLS categories | Linux kernel (LSM) | Every labelled object access | No. Policy is built at boot from `/system` + `/vendor`. |
| **Android permissions** | **Userspace** | Inside the process that serves the data | **Yes. Constantly.** |

AOSP's own wording is unambiguous: Android-permission enforcement "is primarily done in userspace by the
data/service provider". That is the whole game. The kernel will stop an attacker from `open()`ing another
app's `shared_prefs/auth.xml`, deterministically and without exception. The kernel will not stop that same
app from calling your exported `ContentProvider` and asking politely for the same bytes over Binder. Whether
that call succeeds is decided by a few lines of Java that your target's developer wrote, in a method that
runs on a Binder thread, under time pressure, three years ago.

So the question "where are the bugs?" has a structural answer, not a statistical one. The bugs are wherever
the app *left the sandbox on purpose*, because that is the only place where a human decision replaced a
kernel decision.

### The two failure modes

Nearly every high-severity Android application finding is one of exactly two mistakes at that join:

**1. The app EXPORTS something it should not.**
A component, a provider authority, a binder interface, an intent filter, a `PendingIntent`, a URI grant, a
file mode, a backup rule, a JavaScript bridge. Something that was supposed to be internal is reachable by a
principal the developer never modelled. The classic shape is an unauthenticated caller reaching an
authenticated action: *permission re-delegation*, or the confused deputy — the app lending the permissions
the user granted *it* to any app that asks.

**2. The app TRUSTS data crossing that boundary that it should not.**
An `Intent` extra, a nested `Intent`, a `Bundle` it forwards, a deep-link parameter, a `content://` URI from
a foreign provider, a `DISPLAY_NAME`, a `Parcelable` it unparcels, a server response field, an FCM payload,
a restored `SharedPreferences` file, a downloaded DEX. The data crossed a trust boundary and was then treated
as though it had not.

Most real chains are one of each, joined: an exported component (mistake 1) that forwards attacker-controlled
data (mistake 2) into a sink that executes with the app's identity. Intent redirection is exactly that.
So is the `file://` WebView chain. So is every OTA-update RCE.

### What this means for how you test

Four consequences, and they change what you actually type:

**Test the boundary, not the layer.** "Is there a bug in WebView?" is not a testable question for an
application engagement — WebView is Google's code, updated out of band. "Can attacker-controlled content
reach a `@JavascriptInterface` method that returns this app's session token?" is. Every finding is a
*crossing*, and a crossing has three named parts: an attacker position, a boundary, and a thing obtained.
If you cannot name all three, you have an observation, not a finding. (`docs/05-attacker-models.md` fixes the
first part; `docs/02-severity-and-reportability.md` fixes the third.)

**A missing check is worth more than a weak check.** Because permission enforcement is userspace code, the
interesting failures are not cryptographic; they are *ordering and API-selection* failures. The check is in
`onBind()` instead of in the method. The check is `checkSelfPermission()` instead of `checkCallingPermission()`.
The check runs after `clearCallingIdentity()`. The check validates the action and never the caller. You find
these by reading, not by fuzzing.

**The kernel gives you a free oracle.** When you claim a crossing happened, SELinux will tell you whether it
did. An `avc: denied` line with `permissive=0` is proof your claim is false; the absence of one alongside
returned bytes is proof it is true. Use it on yourself before a triager uses it on you.

**Anything decided inside the app's own process is advisory.** ART runs the client under the device owner's
control. Root detection, pinning, entitlement checks, price calculations, "is this device trusted" booleans,
purchase verification — all of it is a suggestion to the server, and the finding is never that you bypassed
it. The finding is what the *server* did when you told it something false. This single distinction is the
difference between a P5 graveyard report and a P1.

---

## Layer by layer, from the tester's seat

AOSP's stack is five layers plus apps: Linux kernel → HAL → native libraries and daemons → the Android
Runtime and the Java API framework → system services → system apps → your target. Below, each layer gets the
same four questions: what it is, what of it is reachable **from a third-party app** or **from the app under
test**, what you actually probe, and which checklist domain owns it.

Run this once, at the start of every engagement, before anything else:

```bash
PKG=com.target.app
PID=$(adb shell pidof $PKG)
adb shell ps -A -Z | grep $PKG                                  # UID + SELinux domain + MLS categories
adb shell cat /proc/$PID/status | grep -E 'Uid|Gid|Groups|Seccomp|NoNewPrivs'
adb shell cat /proc/$PID/maps | awk '{print $6}' | sort -u | grep -E '\.so|\.apk|\.oat|\.vdex|\.art|\.dex'
adb shell ls -l /proc/$PID/ns/                                  # mount/net/user namespaces
adb shell cat /proc/$PID/mountinfo | grep -E 'apex|storage|data'
adb shell ls -lZ /proc/$PID/fd/ 2>/dev/null | grep -E 'kgsl|mali|dri|binder'
```

That output is a layer map of one process. Everything below tells you how to read it.

### 1. The Linux kernel

**What it is.** A GKI (Generic Kernel Image) core from ACK 5.10+ on modern devices, separated from
hardware-specific code by the KMI, with vendor functionality delivered as loadable modules (DLKMs). It owns
DAC, SELinux/MAC, seccomp filtering, the Binder driver, and every device node.

**What is reachable.** From an app: the syscall set that survives the seccomp-bpf filter applied to every app
since Android 8; `ioctl(BINDER_WRITE_READ)` on `/dev/binder`; and — this is the one testers miss — **GPU
device nodes held open inside the app's own process** (`/dev/kgsl-3d0`, `/dev/mali0`, `/dev/dri/*`), because
graphics HALs are same-process. An in-process memory bug is therefore adjacent to a kernel driver handle, not
merely to "the app crashes".

**What you probe.** `Seccomp: 2` in `/proc/<pid>/status` (filter mode). `uname -a`, `/proc/version`,
`ro.build.version.security_patch`, `lsmod`. The hardening sysctls: `kptr_restrict`, `dmesg_restrict`,
`perf_event_paranoid`. Record all of it as *environment*. AOSP's own hardening list — seccomp, hardened
usercopy, KASLR, PAN emulation, read-only-after-init, HWASan, BoundSan, IntSan, XOM, Scudo, ShadowCallStack
— raises exploitation cost; it does not remove bugs, and it is not something you report on.

**Domain.** `D16` (as the ceiling on an in-process native finding), `D25` (as environment). **Never file
"old kernel" as an application finding.**

### 2. The HAL

**What it is.** Three flavours, and the difference is entirely a security difference. *Binderised* HALs run
as separate vendor processes reached over `/dev/hwbinder` (HIDL) or `/dev/vndbinder` (vendor AIDL).
*Passthrough* HALs are shims. *Same-process* HALs (SP-HALs) are "a restricted set of wrapped interfaces
controlled by Google that run directly within client processes" — OpenGL, Vulkan, RenderScript,
`android.hidl.memory@1.0`, the stable C mapper.

**What is reachable.** Here is the fact that kills most over-rated HAL findings: **apps talk on `/dev/binder`
only.** Android maintains three isolated binder contexts, and "binder nodes passed through a specific context
are accessible only within that same context". A vulnerability in a HIDL HAL is not an app-level finding
unless you can name a framework service on `/dev/binder` that proxies to it, and show `getService()` returning
non-null for that name **from the app's UID**. Conversely, the SP-HALs are *inside* the app's address space —
vendor code, generally unaudited, parsing shaders, textures, image data and RenderScript kernels, in the app's
sandbox.

**What you probe.**
```bash
adb shell ls -lZ /dev/binder /dev/hwbinder /dev/vndbinder
adb shell cat /vendor/etc/vintf/manifest.xml       # OEM-declared AIDL/HIDL services
adb shell lshal 2>/dev/null | head -50
adb shell service list                             # the app-reachable surface
adb shell cat /proc/$PID/maps | grep -E 'vendor|libGLES|libvulkan|libRS|mali|adreno|powervr'
```
A `<hal format="aidl"><name>vendor.oem.foo</name><fqname>IFoo/default</fqname></hal>` entry that is not in
AOSP, cross-referenced against a `service list` name your app UID can obtain, is the classic OEM VRP finding.

**Domain.** `D16` for the in-process SP-HAL surface, `D25` for vendor services. Confirm scope before touching
`D25` at all — OEM services are usually out of scope on an application engagement.

### 3. Native libraries, daemons and the linker

**What it is.** `libc`, `liblog`, `libutils`, `libbinder`, `libselinux`; `init`, `logd`, `storaged`. Plus the
dynamic linker's **namespace** model: framework processes get `default`, `sphal`, `vndk` and `rs` namespaces
with their own `search.paths`, `permitted.paths` and `visible` flags; apps get a `classloader-namespace`.

**What is reachable.** From targetSdk 24 an app may only `dlopen()` libraries on the public allowlist
(`/system/etc/public.libraries.txt`, `/vendor/etc/public.libraries.txt`, plus OEM
`public.libraries-COMPANYNAME.txt` files whose members must be named `lib*COMPANYNAME.so`). From API 31 an app
must declare non-APK native libraries with `<uses-native-library>`. So a `System.load()` of an absolute path
outside the APK is always interesting: it is either a vendor blob (OEM-specific behaviour — the app's posture
now varies by device image) or a file the app wrote at runtime (a dynamic-code-loading path).

**What you probe.**
```bash
grep -RnE 'System\.load\(|System\.loadLibrary\(|dlopen' out/sources/ | grep -vE 'loadLibrary\("(c|m|log|android|jnigraphics)"'
adb logcat | grep -iE 'dlopen failed|is not accessible for the namespace'
adb shell cat /system/etc/public.libraries.txt
grep -n 'uses-native-library' out/AndroidManifest.xml
```
The interesting output is a loaded path plus `ls -lZ` showing it is writable by anything other than the app's
own UID. That is not a storage finding; that is native code execution in the app's UID.

**Domain.** `D16`, `D17`, `D02`.

### 4. ART and the Java API framework

**What it is.** One ART instance per app process, running DEX compiled by `d8` and optimised on device by
`dex2oat`. On top of it, the `android.*` API surface — but the important observation is that almost none of
that API is *in* your process. `ActivityManager`, `PackageManager`, `ClipboardManager`, `NotificationManager`,
`LocationManager`, `KeyStore`: these are thin proxies that marshal a Parcel and `transact()`.

**What is reachable.** Everything the app can name. The value of this layer to a tester is that hooking it
gives total coverage: an app cannot make a privileged request without crossing Binder, and it cannot serve one
without `Binder.execTransact`. Third-party SDKs that never touch the app's own Java classes still show up here.

**What you probe.** Instrument the boundary, not the API:
```javascript
Java.perform(function () {
  var BP = Java.use("android.os.BinderProxy");
  BP.transact.implementation = function (code, data, reply, flags) {
    var iface = ""; try { iface = this.getInterfaceDescriptor(); } catch (e) {}
    console.log("[->] " + iface + " code=" + code + (flags & 1 ? " ONEWAY" : "") + " size=" + data.dataSize());
    return this.transact(code, data, reply, flags);
  };
  var B = Java.use("android.os.Binder");
  B.execTransact.overload('int','long','long','int').implementation = function (code, dp, rp, flags) {
    console.log("[<-] incoming code=" + code + " callingUid=" + B.getCallingUid());
    return this.execTransact(code, dp, rp, flags);
  };
});
```
The outgoing log is the app's true dependency graph. The incoming log is the *authoritative* list of what the
app serves — including runtime-registered receivers and dynamically published interfaces that appear in no
manifest.

**Domain.** `D06`, `D08`, `D26`.

### 5. System services

**What it is.** `system_server` (UID 1000, holding most framework services), plus `SurfaceFlinger`,
`MediaService` and friends. Registered with `servicemanager` and reachable on `/dev/binder`.

**What is reachable.** Two gates stack here, and you must distinguish them. First, SELinux decides whether
your domain may `find` the service at all — a denial shows as `avc: denied { find }` and `getService()`
returns null. Second, the service's own method decides whether to honour the call, using
`Binder.getCallingUid()` / `checkCallingPermission()`. On stock AOSP this is well-reviewed code. On OEM images
it is where vendor-added methods appear with the permission check quietly dropped.

**What you probe.**
```bash
adb shell service list; adb shell dumpsys -l; adb shell cmd -l
```
then, from *inside the target UID* (this is the reachability that matters, not the shell's):
```javascript
Java.perform(function(){
  var SM = Java.use("android.os.ServiceManager");
  SM.listServices().forEach(function(n){
    console.log((SM.getService(n) ? "REACHABLE " : "denied    ") + n);
  });
});
```

**Domain.** `D25` primarily; `D06` when the app under test depends on one.

### 6. System and privileged apps

**What it is.** `/system/app`, `/system/priv-app`, and their `/product`, `/vendor` and `/system_ext`
equivalents. Privileged apps run in the `priv_app` SELinux domain and may hold `signature|privileged`
permissions — but only if allowlisted in `/etc/permissions/privapp-permissions-*.xml` **on the same
partition**. From Android 9 a violation blocks boot, unless `ro.control_privapp_permissions=log`.

**What is reachable.** Every exported component of every preinstalled app, from any installed app. This layer
is where the *deputies* live: an app holding `WRITE_SECURE_SETTINGS` or `INSTALL_PACKAGES` that exposes an
under-guarded component turns any zero-permission app into the holder of those capabilities. It is also where
your target may exist in a second, more privileged form: the OEM-bundled build of the same app runs as
`priv_app`, and the identical code defect is a far higher-severity finding there.

**What you probe.**
```bash
adb shell dumpsys package com.target.app | grep -E 'codePath|flags=|privateFlags=|pkgFlags='
adb shell ps -A -Z | grep target                     # priv_app vs untrusted_app
adb shell getprop ro.control_privapp_permissions     # expect "enforce"
adb shell cat /etc/permissions/privapp-permissions*.xml | grep -A10 com.target.app
adb logcat -b all | grep -E 'not in privapp-permissions allowlist|not in signature permission allowlist'
```

**Domain.** `D25`, and it escalates every `D04`–`D08` finding by a level.

### 7. The app under test

**What it is.** One UID, possibly several processes, one ART instance per process, and **no intra-app
sandbox whatsoever**. Every bundled SDK — analytics, ads, crash reporting, the "security" SDK — executes with
the app's UID, the app's granted permissions, the app's Keystore aliases and the app's network identity.

**What is reachable, and by whom.** This is the inventory the rest of the engagement consumes:
```bash
apktool d -f -o out app.apk
adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Permissions:/p'
adb shell ps -A -o PID,USER,NAME | grep com.target.app       # process topology
grep -Rn 'android:process' out/AndroidManifest.xml
```
Two traps here. First, read the **merged** manifest from the APK, never the source manifest: build-time
manifest merging pulls in components from libraries that the app's own source never declares, and those are
routinely exported. Second, `android:process` creates a separate *address space*, not a separate *sandbox* —
multiple PIDs with distinct names but an identical `u0_aNNN` USER column disproves any "our payment WebView
runs isolated" claim on the spot. The only real in-app containment boundary is
`android:isolatedProcess="true"`, which since Android 4.1 runs a service "with no Android permissions and
access to only two binder services".

**Domain.** All of `D01`–`D23`.

---

## Binder: the universal trust boundary

Everything above the kernel talks over Binder. If you understand one subsystem deeply, make it this one.

### Parcel and Bundle marshalling

An AIDL call becomes: "a method identifier and all of the objects are packed onto a buffer and copied to a
remote process where a binder thread waits to read the data." That buffer is a `Parcel`, and three properties
of it matter:

1. **A Parcel carries live capabilities, not just bytes.** It can hold `IBinder` references and file
   descriptors. A returned `ParcelFileDescriptor` is a real, open kernel FD in the receiving process, with
   whatever access mode it was opened with. Check `/proc/<attacker-pid>/fd/` after any IPC call — a symlink
   into `/data/data/com.target.app/…` that your UID could never `open()` directly is a sandbox-crossing read,
   and if it is writable it is a stored-injection primitive.
2. **A `Bundle` is length-prefixed and lazily unparcelled.** It carries a magic value (`0x4C444E42`) and a
   length, and its contents are not materialised until someone asks for a key. That laziness is the entire
   basis of the mismatch bug class: a `Parcelable` whose `writeToParcel` and `createFromParcel` do not consume
   the same number of bytes lets an attacker hide extra key/value pairs, so a validating reader sees a benign
   `Bundle` and a later reader sees additional keys. This is the "self-changing Bundle" / launchAnyWhere
   primitive behind CVE-2017-0806 (`GateKeeperResponse`), CVE-2021-0748 (`ParsingPackageImpl`),
   CVE-2021-0928 (`OutputConfiguration`) and the in-the-wild CVE-2023-20963 (`WorkSource` empty-list
   handling). You hunt it by measuring `Parcel.dataPosition()` deltas across write and read for each of the
   app's own `Parcelable` classes, and a mismatch is the precondition.
3. **Reading one extra unparcels the whole Bundle.** There is no partial trust. A component that "only reads
   the `id` extra" has instantiated every class named in that Bundle, using the supplied `ClassLoader`. Hence
   the API 33 typed overloads — `getParcelableExtra(String, Class<T>)`, `readParcelable(ClassLoader, Class<T>)`
   — which validate the class *before* deserialising. An app on a modern target still using the one-argument
   overloads has kept the type-confusion surface open on purpose.

### What `Binder.getCallingUid()` / `getCallingPid()` guarantee

**They guarantee**, for a genuine remote transaction, that the UID and PID are supplied by the kernel Binder
driver and cannot be forged by the caller. That is a real, strong guarantee, and it is the correct foundation
for an authorisation check.

**They do not guarantee any of the following**, and each line is a live bug class:

- **They are not remote-only.** On a same-process (local) call, `getCallingUid()`/`getCallingPid()` return
  *your own* UID and PID. A helper written as `if (getCallingUid() == Process.myUid()) allow;`, or an
  authorisation routine reachable both locally and remotely, silently passes on the path the attacker
  actually reaches. `getCallingUidOrThrow()` exists precisely to fail closed when there is no remote caller.
- **They are not stable across `clearCallingIdentity()`.** That call swaps the Binder thread's notion of the
  caller to the callee's own identity for the duration. Any `getCallingUid()`, `checkCallingPermission()` or
  `enforceCallingPermission()` executed after it — and before `restoreCallingIdentity()` — evaluates the
  *callee*. Grep the window between clear and restore and read what happens inside it; also flag any clear
  with no `finally { restoreCallingIdentity(token); }`, which leaks the laundered identity onto the exception
  path.
- **A UID is not a package.** `getPackagesForUid()` can return several names; `getNameForUid()` returns a
  `shared:com.example.group` string rather than a package for shared UIDs. An allowlist written as
  `pm.getNameForUid(uid).equals("com.trusted")` or `getPackagesForUid(uid)[0]` fails open or closed
  incorrectly the moment a shared UID is involved.
- **A UID is not a signing key.** Package names are claimable: an attacker sideloads a package with the
  expected name and passes any name-based check. Only `PackageManager.hasSigningCertificate(pkg, cert,
  CERT_INPUT_SHA256)` ties the caller to a key — and even that must handle v3 rotation lineage deliberately,
  because a naive `signatures[0]` comparison still accepts a rotated-away historical certificate.
- **They identify this transaction's peer, not the data's author.** A `PendingIntent` received from a caller
  tells you, via `getCreatorPackage()`/`getCreatorUid()`, who *created* it — never who *sent* it. Any app that
  can obtain the token (notably through a `NotificationListenerService`) becomes the sender while the creator
  stays trusted. From API 34, `BroadcastReceiver.getSentFromUid()`/`getSentFromPackage()` exist, but only work
  when the sender opted in via `BroadcastOptions.isShareIdentityEnabled()` — which is why the broken pattern
  persists on every pre-34 app with no clean fix available.
- **They say nothing about the binder handle's future.** Binder references are first-class transferable
  objects (`Bundle.putBinder`, `Intent.putExtra(String, IBinder)`). A check performed once, at handshake, does
  not bind the session to the party that passed it.

### `oneway` versus blocking transactions

A `oneway` (`FLAG_ONEWAY`) transaction returns immediately. There is no reply Parcel, so the caller learns
nothing about success or failure; ordering is guaranteed only *within a single interface*; and the Binder
driver reserves a separate asynchronous area, so flooding oneway calls exhausts a different budget from
synchronous ones.

The security consequence is a specific shape: **a security-relevant state change implemented as `oneway`
cannot be confirmed by its caller.** Find the `oneway void revokeSession(...)`, `oneway void lock(...)`,
`oneway void invalidateToken(...)` declarations, then demonstrate the caller proceeding down the success path
while the call is dropped (hook `transact` to return true without forwarding). A "revoke" that can be silently
lost leaves a live session.

### Transaction size limits

The Binder transaction buffer is a fixed region of roughly 1 MB **shared by all in-flight transactions of a
process**. `TransactionTooLargeException` is therefore not purely a caller-side bug: an attacker who can make
the target hold many or large transactions can cause *unrelated, legitimate* transactions in that process to
fail. On its own that is a Medium availability issue. The finding is in the catch block:

```bash
grep -RnE 'TransactionTooLargeException|catch \(RemoteException|DeadObjectException' -A8 out/sources/
```

An entitlement check, a permission check or a "is this device trusted" query whose `catch (RemoteException)`
branch returns `true` is a fail-open control with a remotely triggerable trigger.

### Death recipients

`linkToDeath(DeathRecipient, int)` and `isBinderAlive()` exist because a server usually has to clean up a
client's session when the client dies. If authorisation state is keyed to a binder token but cleanup happens
only in `binderDied()`, then a client that keeps the token alive — or an attacker who received a relayed token
— keeps a privileged session that outlives the process that earned it. The PoC is two apps and a
`force-stop`: obtain the binder in app A, relay it to app B, kill A, and show B's calls still succeed.

### Why "validates the action but never the caller" is the single most repeated mistake

Because it is what the code *looks like it should do*. A service method receives a request, the developer
validates the request thoroughly — bounds, types, nulls, state machine, business rules — and never asks who
made it. Every symptom below is a variant of that same blind spot, and together they account for more
high-severity Android IPC findings than every other category combined:

| Shape | Why it fails |
|---|---|
| `checkSelfPermission(P)` in an exported entry point | Asks "do **I** hold P". Always true for a permission the app declared. Not an access control at all. |
| `checkCallingOrSelfPermission(P)` / `enforceCallingOrSelfPermission(P)` | Succeeds if **either** side holds P. The privileged callee always holds it, so the caller is never tested. |
| `checkCallingPermission(P);` as a bare statement | Returns an `int` (`PERMISSION_GRANTED`/`PERMISSION_DENIED`). It does not throw. Discarding the return value is a no-op guard. |
| Check in `onBind()` only | `onBind()` runs once per binding, and is **not** called again for a second client of an already-running service — the same `IBinder` is returned. Relay the handle to an unprivileged app and every method is open. |
| Check on method 1, absent on method 7 | Per-method asymmetry inside one interface. Enumerate and call *every* method; the unguarded sibling is the finding. |
| `getCallingPackage()` inside a provider | Returns the package of the calling *process* only when there is a live binder identity; the unchecked variant and the local-call case both mislead. Pair any package answer with a signature check. |
| Check after `clearCallingIdentity()` | Evaluates the callee. See above. |
| `getCreatorPackage()` on a received `PendingIntent` | Authenticates the creator, not the sender. |
| Validation in the *proxy* class, sink reached via a second path | The classic "find the unguarded sibling call site": the validator exists and is correct; some other caller does not use it. |

The correct pattern, and the one to cite in remediation, is a per-method caller interrogation:
`enforceCallingPermission(P, msg)`, or `context.checkPermission(P, Binder.getCallingPid(),
Binder.getCallingUid())`, plus — where identity rather than permission is the question —
`PackageManager.hasSigningCertificate()` against a pinned digest.

---

## Zygote, and why your CA install failed

### Fork semantics

`init` starts the zygote. The zygote preloads the framework classes and resources, then **forks** for every
new app process; the child is then *specialised* — its UID, GIDs, SELinux context, cgroup, nice value and
capability set are set after the fork, not before. Modern builds additionally keep a pool of pre-forked,
unspecialised processes (USAP, `dalvik.vm.usap_pool_enabled`) to cut launch latency. WebView gets its own
`webview_zygote`, which is why you will see `webview_zygote` and `…:sandboxed_process0` in `ps`.

Two testing consequences fall straight out of fork semantics. The first is FD hygiene: AOSP's own zygote
documentation carries an `fds_to_ignore` mechanism precisely because inherited file descriptors are a
recognised leak class at the platform level — so an FD open in the zygote is an FD open in every app. The
second is the one that ruins engagements.

### Mount-namespace inheritance

**Each Zygote-forked app process gets its own mount namespace.** The storage subsystem relies on this to give
each app its own view of external storage, and `/apex` is mounted with `PRIVATE` propagation. The practical
meaning is brutal and non-obvious:

> A mount you perform in the `adb shell`'s mount namespace is **invisible** to every running app process.

Combine that with the APEX layout (next section) and you get the most common false negative in mobile
testing. On API 34+ the live TLS trust store is `/apex/com.android.conscrypt/cacerts`. A tester drops a CA
into `/system/etc/security/cacerts`, sees no traffic in Burp, and writes "the application implements
certificate pinning". It does not. The CA was never in the store the app reads, and even a correct bind mount
performed from the shell never reached the app's namespace.

### The harness consequence, in full

```bash
# 1. stage a writable copy of the trust store
adb shell su -c '
  mkdir -p /data/local/tmp/certs
  cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/certs/ 2>/dev/null
  cp /system/etc/security/cacerts/*        /data/local/tmp/certs/ 2>/dev/null
'
# 2. add your CA under the hashed name Conscrypt expects
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
adb push burp.pem /data/local/tmp/certs/$HASH.0

# 3. tmpfs over the legacy directory, populate it, and label it correctly
adb shell su -c '
  mount -t tmpfs tmpfs /system/etc/security/cacerts
  cp /data/local/tmp/certs/* /system/etc/security/cacerts/
  chown root:root /system/etc/security/cacerts/*
  chmod 644 /system/etc/security/cacerts/*
  chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/*
'

# 4. THE STEP EVERYONE MISSES — inject into the zygote mount namespace,
#    so every process forked from here on inherits it
adb shell su -c '
  for Z in $(pidof zygote) $(pidof zygote64); do
    nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind \
      /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
  done
'

# 5. and into every already-running app process
adb shell su -c '
  for P in $(ls /proc | grep -E "^[0-9]+$"); do
    nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind \
      /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null
  done
'
```

**Verify from inside the target's namespace, never from the shell's** — and the difference between the two
views *is* the proof that namespaces matter:

```bash
PID=$(adb shell pidof com.target.app)
adb shell su -c "nsenter --mount=/proc/$PID/ns/mnt -- ls /apex/com.android.conscrypt/cacerts | wc -l"
adb shell ls /apex/com.android.conscrypt/cacerts | wc -l         # the shell's view — may differ
adb shell readlink /proc/$PID/ns/mnt; adb shell readlink /proc/self/ns/mnt   # different inodes
adb shell cat /proc/$PID/mountinfo | grep -E 'cacerts|conscrypt'
```

There is a per-process alternative that avoids namespace surgery entirely. Conscrypt's
`SystemCertificateSource` checks the Java system property `system.certs.enabled`, and when it is `"true"`
reads `$ANDROID_ROOT/etc/security/cacerts` instead of the APEX path:

```javascript
// frida -U -f com.target.app -l this.js --no-pause   (must run BEFORE the first TLS use)
Java.perform(function () {
  var S = Java.use("java.lang.System");
  S.setProperty("system.certs.enabled", "true");
});
```

Use it with steps 1–3 above. It requires spawn mode, because the property must be set before the app's first
TLS handshake.

**Why this sits in a conceptual document rather than only in the lab guide:** a harness error here does not
produce a wrong finding, it produces a *silently absent domain*. `D14`, `D15`, `D17`, `D18` and `D24` all
depend on seeing the wire. If you get this wrong you will hand the client a report whose network section is
blank and whose stated reason is false.

---

## ART and where a write becomes execution

### DEX, oat, vdex — and what actually executes

`d8` produces DEX at build time. On device, `dex2oat` produces three artefact types, and the compiler filter
decides which:

| Artefact | Contains | Notes |
|---|---|---|
| `.vdex` | Verification metadata; sometimes the uncompressed DEX itself | Lets re-compilation skip verification |
| `.odex` | AOT-compiled native method code | This is what the CPU runs |
| `.art` | ART's internal representation of hot classes/strings | Startup acceleration |

They live under `/data/app/~~<random>/<pkg>-<random>/oat/<abi>/` and, for on-device compilation,
`/data/dalvik-cache/<abi>/`. Compiler filters are `verify`, `quicken` (Android 11 and lower), `speed` and
`speed-profile`; profile-guided recompilation is scheduled by the system, and `dalvik.vm.usejit`,
`dalvik.vm.jitthreshold` and `dalvik.vm.jitmaxsize` (default 64 M) govern the JIT.

The security consequence is quiet but important: **the code that executes is the `.odex`/`.vdex`, not the
APK.** An app that verifies its own APK signature at runtime — `getPackageInfo(GET_SIGNING_CERTIFICATES)`,
a CRC, a bundled hash — has verified an artefact that is not the one running, using data supplied by a
`PackageManager` proxy that an instrumented process controls. Demonstrate the gap rather than describing it:
inject code, show your own log line from inside the process, and show the integrity check still reporting
"intact". Report it as a broken control (Medium), not as compromise.

### Class loaders

- `PathClassLoader` — the app's own, parent-first.
- `DexClassLoader` — loads DEX/JAR/APK from an arbitrary path.
- `InMemoryDexClassLoader` — loads from a `ByteBuffer`; the code never touches the filesystem and never
  appears in the APK.
- `DelegateLastClassLoader` — inverts delegation order, so a class in the supplied path wins over the parent.
  Shadowing opportunities live here.
- `createPackageContext(pkg, CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)` followed by `getClassLoader()`
  — loads **another package's code into your process**, with `CONTEXT_IGNORE_SECURITY` skipping the
  certificate check. Any app that claims the expected package name gets its code executed inside the target,
  with the target's UID, permissions and Keystore. The attacker side needs only a package with the right name
  and an exported `android:appComponentFactory`.

### The exact shape of file-write-to-code-execution

This is the shape worth memorising, because it converts a mundane storage finding into a Critical:

> **(1)** A path writable by some principal other than the app's own UID, **and**
> **(2)** the same path later passed to a class loader, to `System.load()`, or extracted and `dlopen()`ed,
> **and** **(3)** no signature or hash verification of the content before it is loaded.

All three, or it is not code execution. Two of three is a hardening note. So the method is an intersection,
not a search: enumerate the *loaded* set and the *writable* set separately, then intersect.

```bash
# the loaded set
grep -RnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|DelegateLastClassLoader|BaseDexClassLoader|System\.load\(' -A4 out/sources/
frida-trace -U -n com.target.app -j 'dalvik.system.DexClassLoader!$init' -j 'dalvik.system.BaseDexClassLoader!$init'

# the writable set
adb shell run-as com.target.app find . -type f \( -name '*.dex' -o -name '*.jar' -o -name '*.apk' -o -name '*.so' -o -name '*.zip' \) -exec ls -lZ {} \;
adb shell ls -lZ /sdcard/Android/data/com.target.app/files/ 2>/dev/null
adb shell run-as com.target.app ls -l code_cache/ files/ no_backup/
```

The writers to consider are broader than "a world-writable file". Each of these has produced real findings:

- group/other write bits, or any path under `/sdcard`;
- a writable `ParcelFileDescriptor` handed out over Binder (`MODE_READ_WRITE` on a file the caller should
  only read);
- a zip-extraction loop that concatenates `entry.getName()` onto a base directory with no canonicalisation
  (`../lib/arm64/libfoo.so` overwrites a loaded library);
- a foreign `ContentProvider`'s `OpenableColumns.DISPLAY_NAME` used as a destination filename;
- an OTA/hot-patch channel (CodePush, expo-updates, Tinker, a bespoke "hotfix" SDK) that is unpinned,
  unsigned, or signed with a key that ships in the APK;
- a symlink swapped in between a path validation and the later `open()`.

From Android 14 (targetSdk 34) the platform requires a dynamically loaded file to be marked **read-only
before content is written**, and throws otherwise. The mitigation's existence names the bug it prevents:
`setReadOnly()` called *after* the write leaves a substitution window. Grep the ordering explicitly; and grep
`adb logcat` for the platform's refusal message when the ordering is wrong.

Finally, two reasons static review alone under-reports here. Packers and some SDKs decrypt a `.so` or `.dex`
at runtime and load it via `memfd_create` + `android_dlopen_ext` or `InMemoryDexClassLoader` — code that is
simply not in the APK, and must be dumped from RX mappings at runtime. And because ART has been a Mainline
APEX since Android 12, an app whose hardening depends on non-SDK interfaces or internal ART structures can
have that hardening silently disabled by a Google Play system update, with no OS upgrade at all
(`adb logcat | grep -iE 'Accessing hidden (method|field)'`).

---

## APEX / Mainline

### What moved out of `/system`

Since Android 10, large parts of the platform ship as independently updatable modules delivered by Google Play
system updates, not by an OS upgrade. The ones that matter to a tester:

| Module | Package | Why you care |
|---|---|---|
| ART | `com.android.art` | The runtime itself is updatable (APEX from Android 12). Non-SDK/internal-ART reliance can break under it. |
| Conscrypt | `com.android.conscrypt` | **The TLS stack, the JCA providers, and the CA trust store.** |
| DNS resolver | `com.android.resolv` | Resolution policy, Private DNS/DoT. |
| Media, Bluetooth, etc. | `com.android.media`, `com.google.android.bt` | App-reachable parser CVEs live or dead depending on module version. |
| PermissionController | (APK module) | The runtime-permission UI and policy. |

An APEX file is a ZIP containing `apex_manifest`, `apex_payload.img` and `apex_pubkey`, dual-signed — AVB
(libavb) over the payload and APK Signature Scheme v3 over the container. `apexd` mounts the payload on a loop
device under dm-verity at `/apex/<name>@<version>`, then **bind-mounts the active version to `/apex/<name>`**.
That is why `ls /apex` shows both a versioned directory and a bare name for the same module.

```bash
adb shell ls -l /apex | grep '@'
adb shell cmd package list packages --apex-only --show-versioncode
adb shell getprop ro.build.version.security_patch
```

### Consequence 1: patch level is not the answer to "is this patched?"

`ro.build.version.security_patch` tells you about the OS image. Whether a given framework CVE is fixed on this
handset depends on the **module version**. On a fleet where an MDM pins or blocks Play system updates, a stale
Conscrypt, Media or DNS-resolver module is a real, evidenced exposure window on a device the client controls
— and it is the module version, not the patch string, that evidences it.

### Consequence 2: the API 34+ trust store

On Android 14 and later the live CA set is `/apex/com.android.conscrypt/cacerts`. Two things follow, and they
point in opposite directions:

**For your harness.** Editing `/system/etc/security/cacerts` accomplishes nothing. See the zygote section
above for the correct procedure; `adb shell ls /apex/com.android.conscrypt/cacerts | wc -l` versus
`adb shell ls /system/etc/security/cacerts | wc -l` tells you at a glance which directory is populated on this
device.

**For the target.** Any app-side hardening that reads `/system/etc/security/cacerts` to detect a user-installed
MitM CA — enumerating it, hashing it, comparing a count — is a **no-op** on API 34+. If the client's threat
model or marketing claims "we detect proxy CAs", that control is disproved with two `ls` commands, before you
attack the TLS path at all. Grep for it:

```bash
grep -RnE '/system/etc/security/cacerts|/apex/com\.android\.conscrypt|ANDROID_ROOT|system\.certs\.enabled' out/sources/ out/smali*/
```

### Consequence 3: the crypto provider is replaceable, and replacing it opts out of Mainline

Conscrypt (wrapping BoringSSL) is the platform's default JCA and TLS provider, and it is what enforces
platform TLS policy — including Android 15 disallowing TLS 1.0 and 1.1 for apps targeting it. An app that
calls `Security.insertProviderAt(new BouncyCastleProvider(), 1)`, or that ships its own OpenSSL/BoringSSL in a
`.so`, or that runs a cross-platform engine with its own TLS stack, has opted every crypto operation in the
process out of Mainline security updates — and out of the platform TLS floor.

```bash
grep -RnE 'Security\.insertProviderAt|Security\.addProvider|BouncyCastleProvider|org\.spongycastle|removeProvider' out/sources/
unzip -l app.apk | grep -iE 'bcprov|spongycastle|conscrypt'
strings out/lib/arm64-v8a/*.so | grep -iE 'TLSv1|OpenSSL [0-9]|BoringSSL' | sort -u
```

A bundled provider pinned at an old release is a concrete, versioned exposure, not a style objection.

---

## The permission model, precisely

### The base levels and the flag bits

`protectionLevel` is a single integer: the **base level is the low nibble**, and everything above it is
modifier flags. Read the *enforced* value from `PackageManager`, never only the manifest string, because the
two can diverge — another package may have defined the name first, or an OEM may have overridden it.

```bash
adb shell pm list permissions -f -g | grep -B4 -A4 'com.target.permission'
adb shell dumpsys package com.target.app | sed -n '/declared permissions/,/requested permissions/p'
```

| Base level | Value | Meaning |
|---|---|---|
| `normal` | 0 | Granted at install, silently, to any app that asks. **Not an access control between apps.** |
| `dangerous` | 1 | Runtime prompt, granted per *group*, by a user who mostly taps yes. |
| `signature` | 2 | Same signing key **as the definer** — which is the platform key only for platform-defined permissions. |
| `signatureOrSystem` | 3 | Deprecated at API 23. Old synonym for `signature|privileged`. Treat its presence as a red flag. |
| `internal` | 4 | A no-op base level that exists to be combined with flags. An `internal` permission with no meaningful flag is not a control. |

| Flag | Bit | What it changes |
|---|---|---|
| `privileged` / `system` | `0x10` | Grantable to `/system/priv-app` apps, subject to the privapp allowlist. |
| `development` | `0x20` | **Grantable over adb with `pm grant`**, despite being signature-protected. |
| `appop` | `0x40` | The manifest declaration is a *display*; the app-op is the real gate. |
| `pre23` | `0x80` | Grantable only to apps targeting below 23. |
| `installer` / `verifier` / `preinstalled` / `setup` / `instant` | `0x100`–`0x1000` | Role-of-package gates. |
| `runtimeOnly` | `0x2000` | Never granted at install. |
| `role` | `0x4000` | Granted to whoever currently holds a system Role (default SMS app, dialer, HOME…). |
| `knownSigner` | `0x8000` | Granted to any app whose signing certificate is in the `android:knownCerts` allowlist (Android 12+). |

In-app, `PermissionInfo.getProtection()` returns the base and `getProtectionFlags()` the OR of the modifiers.
Three of these deserve a tester's attention immediately:

- **`development`** — if the target guards a diagnostic surface with a development-flagged permission, anyone
  with adb (a malicious desktop, a USB-debug session, a compromised MDM) takes it with one command. Those
  surfaces routinely expose tokens, request logs, or a "set backend URL" control.
- **`knownSigner`** — the allowlist is a hard-coded set of SHA-256 digests in the manifest. Enumerate it.
  Any party holding one of those keys takes the permission, including a deprecated partner or a key the
  target rotated away from.
- **`role`** — role acquisition is user-visible but low-friction, and the resulting grant is silent and total.
  SMS role → OTP interception. HOME role (plus `ACCESS_HIDDEN_PROFILES`) → Private Space visibility.

A permission element with **no** `protectionLevel` attribute silently defaults to `normal`. That single
omission has produced more custom-permission findings than any deliberate design choice.

### Runtime, special and app-op permissions

Runtime (`dangerous`) permissions arrived in Android 6.0 and are grouped by `permissionGroup`; the group, not
the individual permission, is what the user sees, "to avoid over-prompting". Two consequences: a custom
`dangerous` permission that names a *platform* group can ride along with a platform grant from a single tap,
and group membership can change without notice.

**Special permissions** (`SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`, `MANAGE_EXTERNAL_STORAGE`,
`REQUEST_INSTALL_PACKAGES`, `SCHEDULE_EXACT_ALARM`, `USE_FULL_SCREEN_INTENT`) carry the `appop` flag. The
manifest entry is necessary but not sufficient; the decision lives in the app-op state, and the correct
app-side checks are `Settings.canDrawOverlays()`, `Settings.System.canWrite()`,
`Environment.isExternalStorageManager()`, `PackageManager.canRequestPackageInstalls()`,
`AlarmManager.canScheduleExactAlarms()`.

**App-ops** are the enforcement layer underneath the permission model, and their modes matter:

| Mode | Behaviour |
|---|---|
| `MODE_ALLOWED` | Access granted. |
| `MODE_IGNORED` | **Denied silently.** The API returns empty or no-ops; nothing is thrown. |
| `MODE_ERRORED` | Throws `SecurityException`. |
| `MODE_FOREGROUND` | Allowed only while the app is in the foreground. |
| `MODE_DEFAULT` | Fall back to the traditional permission grant state. |

`MODE_IGNORED` is the interesting one. It is how "allow only while using the app" is implemented — the op
flips to `MODE_IGNORED` when the app leaves the foreground rather than throwing — and it is how you disable a
control during testing without touching the app:

```bash
adb shell appops get com.target.app
adb shell appops set com.target.app SYSTEM_ALERT_WINDOW ignore
adb shell dumpsys appops | sed -n '/com.target.app/,/^  Uid/p'
adb shell appops reset com.target.app
```

Two bug classes follow. An app that treats "no exception" as "access granted" mis-handles the denial. And a
*defensive* feature built on such a permission — an overlay-based tamper warning, a screenshot guard — can be
made to fail open silently by an attacker who can set the op, which is a real finding and not a test artefact.

**Restricted permissions** add a further wrinkle: hard-restricted permissions cannot be granted at all without
an allowlist entry, and the allowlist can be set by the **installer** via
`PackageInstaller.SessionParams.setWhitelistedRestrictedPermissions()`. On an app-store or enterprise-installer
engagement, that call is an access-control decision made by a third party on the user's behalf. Read the grant
flags, not just the boolean:

```bash
adb shell dumpsys package com.target.app | sed -n '/runtime permissions/,/^$/p'
# flags to look for: USER_SET, USER_FIXED, SYSTEM_FIXED, GRANTED_BY_DEFAULT,
#                    RESTRICTION_UPGRADE_EXEMPT, RESTRICTION_INSTALLER_EXEMPT, RESTRICTION_SYSTEM_EXEMPT
```

A third-party app holding `GRANTED_BY_DEFAULT` or `SYSTEM_FIXED` on a dangerous permission was pre-granted by
`DefaultPermissionGrantPolicy` and the user never saw a prompt — on an OEM engagement that is a direct
violation of the platform's multi-party authorisation rule.

### Squatting, orphans, and the install-order downgrade

Android resolves a duplicated custom-permission **name** on a first-definer-wins basis. That produces three
attacks of descending difficulty and ascending reliability:

**Squatting (needs an install-order race).** The target defines `com.target.permission.SYNC` at `signature`.
An attacker app that defines the same name at `normal` and is installed *first* owns the definition; it is
silently granted the permission, with no user prompt and without the target's key. Android 5.0 tightened
same-name definitions, and CVE-2019-2200 (fixed in Android 10) addressed the uninstall-retains-grant variant —
so establish the tested device's behaviour empirically rather than assuming.

**Protection-level downgrade (needs an uninstall).** If the defining app is uninstalled while peers still
enforce the permission, an attacker redefines the name at a weaker level and the effective level ends up below
what the manifest declares. Test the full lifecycle — install target, install peer, uninstall target, install
squatter, reinstall target — and the evidence is the delta between the manifest string and
`pm list permissions -f`.

**Orphans (needs nothing).** The highest-yield variant, and the one that still works on every current release.
The target protects a component with `android:permission="com.target.permission.X"` but ships no matching
`<permission>` element — a typo, a stale manifest, a permission defined in a module that was dropped, or the
literal `android:permission="True"`. The permission does not exist, so the component is unprotected, and the
attacker simply defines it and is granted it. No race, no user interaction, no window.

```bash
# every permission string the app ENFORCES
grep -oE 'android:(permission|readPermission|writePermission)="[^"]+"' out/AndroidManifest.xml \
  | cut -d'"' -f2 | sort -u > used.txt
# every permission string the app DEFINES
grep -oE '<permission[^>]+android:name="[^"]+"' out/AndroidManifest.xml \
  | grep -oE 'android:name="[^"]+"' | cut -d'"' -f2 | sort -u > defined.txt
comm -23 used.txt defined.txt            # minus genuine android.permission.* names
adb shell pm list permissions -f | grep -c 'com.target.permission.ORPHAN'   # expect 0
```

The attacker APK is about twenty lines:

```xml
<permission android:name="com.target.permission.SYNC" android:protectionLevel="normal"/>
<uses-permission android:name="com.target.permission.SYNC"/>
```

and the proof is three observables together: `pm list permissions -f` naming your package as the definer at
`normal`; `dumpsys package com.attacker` showing `granted=true`; and the previously `SecurityException`-throwing
call now returning data.

One related trap: `<permission-tree>` plus `PackageManager.addPermission()` lets an app add permissions under
a namespace **at runtime**. If the name or level comes from a server response or an intent extra, the attacker
chooses both — and every static analysis of the app's access control is void.

### `sharedUserId`

Two APKs with the same `android:sharedUserId` **and the same signing certificate** run under one Linux UID.
They share a single permission grant-set, can read each other's private data directories, and may share a
process. The security of the strong app therefore equals the security of the weakest sibling: the effective
attack surface is the union of all siblings' exported components, and the effective permission set is the
union of all siblings' permissions.

```bash
grep -n 'sharedUserId\|sharedUserMaxSdkVersion' out/AndroidManifest.xml
adb shell dumpsys package com.target.app | grep -E 'sharedUser|userId='
adb shell pm list packages -U | awk -F: '{print $3}' | sort | uniq -d   # UIDs owning >1 package
adb shell run-as com.sibling.app ls -l /data/data/com.target.app/shared_prefs/
```

It is deprecated at API 29 and "strongly discouraged", but it cannot be removed: migrating off a shared user ID
is unsupported, and `android:sharedUserMaxSdkVersion` (API 33+) is the only forward path — so check which
branch the *tested device* is on before asserting sibling access. Combined with a globally named
`android:process` (no leading colon) it becomes code from the sibling executing inside the target's own
process, with the target's Keystore aliases.

### The distinction that matters most: `checkCallingPermission` versus `checkSelfPermission`

Stated plainly, because it is the single highest-value code review in Android:

- **`checkSelfPermission(P)`** asks *"does my own application hold P?"*. For any permission the app declared,
  it is **always true**. In an exported entry point it is not an access control; it is a comment.
- **`checkCallingOrSelfPermission(P)` / `enforceCallingOrSelfPermission(P)`** succeed when **either** the
  caller **or** the callee holds P. The privileged callee always does. The caller is therefore never tested.
  These exist for code paths that are sometimes local and sometimes remote; using them as a boundary guard is
  the confused deputy, written out longhand.
- **`checkCallingPermission(P)`** interrogates the caller — but it **returns an `int`**
  (`PERMISSION_GRANTED` / `PERMISSION_DENIED`) and does not throw. Code that calls it as a bare statement has
  no guard at all. It is also documented as only working when the call came from another process.
- **`enforceCallingPermission(P, msg)`** is the throwing form, and the one you want to see.
- **`context.checkPermission(P, Binder.getCallingPid(), Binder.getCallingUid())`** is the explicit form, and
  the one the platform's own guidance shows.

```bash
# the bug patterns
grep -RnE 'checkSelfPermission\(|checkCallingOrSelfPermission\(|enforceCallingOrSelfPermission\(' out/sources/
# the correct patterns — and whether they appear at all
grep -RnE 'checkCallingPermission\(|enforceCallingPermission\(|Binder\.getCallingUid\(\)|Binder\.getCallingPid\(\)' out/sources/
# identity laundering
grep -Rn -A20 'clearCallingIdentity()' out/sources/ | grep -nE 'getCallingUid|checkCalling|restoreCallingIdentity'
```

Then prove it dynamically from a zero-permission attacker APK, because a static pattern is a candidate and a
returned token is a finding.

---

## The sandbox, and how to stay honest about escalation

### What the sandbox actually is

- **One Linux UID per application** (`u0_aNNN`), assigned at install. This is the primary boundary and it is
  enforced by the kernel on every file operation.
- **MLS categories per physical user** since Android 6.x, so app A's `c168,c256,c512,c768` cannot touch app
  B's files even where DAC would allow it.
- **A per-app SELinux sandbox**, mandatory for non-privileged apps with `targetSdkVersion >= 28` on Android 9
  and later. Below that, apps share the generic `untrusted_app` domain.
- **seccomp-bpf** on every app process since Android 8.
- **App home directory `0700`** for `targetSdkVersion >= 24` (it was `0751`, i.e. traversable, before that).
- **World-accessible file modes prohibited** for `targetSdkVersion >= 28`; `MODE_WORLD_READABLE` /
  `MODE_WORLD_WRITEABLE` throw.
- **`isolated_app`** as the genuine containment tier: a service declared `android:isolatedProcess="true"` runs
  with no Android permissions and access to only two binder services. Chrome's renderer and WebView's
  `:sandboxed_process` use it.

Read your own position and the target's before claiming anything:

```bash
adb shell ps -Z | grep -E 'com.target.app|com.attacker'
adb shell ls -Z /data/data/com.target.app/
adb shell id -Z                                    # the shell's own context, for contrast
```

A context looks like `u:r:untrusted_app_30:s0:c512,c768` — user, role, type, sensitivity, categories. A
category mismatch between your PoC app and the target is *why* cross-app file access fails, and quoting the
two contexts is how you prove it.

### What `untrusted_app` may actually do

Roughly: transact on `/dev/binder`; `find` the subset of services its domain permits; open its own
`app_data_file` objects whose categories match; open GPU device nodes; read world-readable parts of
`/proc` and the property space; and start components in other apps via the framework. Roughly *not*: read
another app's data directory; reach `/dev/vndbinder` or `/dev/hwbinder`; set most system properties; bind
arbitrary vendor services; or do anything at all that `dmesg` will not tell you about.

### How to name the layer that stopped you

Every claim about reachability should carry either an AVC denial or its documented absence. Capture both:

```bash
adb shell getenforce                               # must be Enforcing for credible results
adb logcat -c; adb shell dmesg -c >/dev/null 2>&1
# ... run the PoC from a real, installed, zero-permission APK ...
adb shell dmesg | grep 'avc: '
adb logcat -b all -d | grep 'avc: '
```

The line you are looking for reads:

```
avc: denied { read write } for pid=8821 comm="poc" \
  scontext=u:r:untrusted_app:s0:c15,c256 tcontext=u:object_r:app_data_file:s0:c512,c768 \
  tclass=file permissive=0
```

`permissive=0` means enforcing, so that denial is real: **the step you were about to claim did not happen.**
Write that down instead of the claim. Conversely, no denial plus returned bytes is affirmative evidence, and
it is far stronger in triage than prose.

### The four honesty rules

**1. `adb shell` is not an attacker.** The shell runs as UID 2000 in its own SELinux domain with far more
privilege than any installed app. Discovery with `adb shell am start` / `content query` is correct and
efficient. A *finding* proved only from adb has not established the zero-permission-app model. Re-prove it
from an installed, differently-signed APK that declares no permissions, and commit that manifest as evidence.
The same applies to Android 13's intent-matching enforcement, which explicitly exempts the system UID and root
— an adb-only PoC can succeed where a real attacker's would fail.

**2. Root on your own device is an evidence tool, not a precondition.** An attacker rooting their own phone to
read their own token has crossed no boundary. Root is legitimate for *showing* that the token you stole over
IPC is the same token in the sandbox. Say which of the two you are doing, every time.

**3. Do not claim an escalation the domain cannot perform.** "…and the attacker then gains root" or
"…then reads other apps' data" needs an AVC-free demonstration or it is fiction. AOSP's own device-policy
guidance notes that excluding `untrusted_app` from a rule is trivially worked around because apps may run
services in `isolated_app` — but that cuts both ways: `isolated_app` is strictly *weaker*, not stronger.

**4. Do not claim persistence you do not have.** An artefact under `/data` persists until factory reset, not
across it; AOSP's rule is that factory reset returns the device to a state determined only by Verified-Boot
covered, integrity-protected partitions. The two documented exceptions are Factory Reset Protection and
Widevine (whose identifier survives reset, scoped to the developer key). Check the partition before writing
"persistent":

```bash
adb shell mount | grep -E ' (/system|/vendor|/product|/data|/system_ext) '
adb shell getprop | grep -E 'ro\.boot\.(verifiedbootstate|flash\.locked|veritymode)'
```

Lastly, use the published adversary taxonomy to make preconditions explicit rather than arguable — physical
classes `[T.P1]`–`[T.P4]`, network `[T.N1]`–`[T.N3]`, application `[T.A1]`–`[T.A8]`, data `[T.D1]`–`[T.D2]`.
`docs/05-attacker-models.md` maps those onto the twelve attacker models this repository rates against.

---

## Keystore, TEE and attestation

### The architecture, and the guarantee it actually provides

Four tiers, and the difference between them is where the raw key bytes live:

| Tier | Key material lives | Compromise resistance |
|---|---|---|
| In-app (`SecretKeySpec`, a hardcoded constant, a derived value) | The app's heap | None against anyone who can read the process or the APK |
| Software-backed `AndroidKeyStore` | An encrypted keyblob held by `keystore2` | Resists other apps; not a rooted device |
| `TrustedEnvironment` (KeyMint TA) | The TEE, typically TrustZone | "Even with a fully compromised kernel, an attacker cannot read key material stored in KeyMint" |
| `StrongBox` | A discrete secure element with its own CPU, storage, TRNG, tamper resistance and secure timer | Strongest; optional from Android 9 |

The `AndroidKeyStore` API itself runs **in the app's own process**; `keystore2` holds only encrypted keyblobs;
the KeyMint TA holds the real material and performs the operation. Authentication tokens are minted by the
Gatekeeper TA and the Fingerprint/Biometric TA and *enforced by KeyMint* — the enforcement is not in the app.
Super-keys are evicted when the device locks.

### Read the key's properties; never accept the claim

An `AndroidKeyStore` alias is not automatically hardware-backed. Establish the truth at runtime:

```javascript
Java.perform(function () {
  var KS = Java.use('java.security.KeyStore'), KF = Java.use('java.security.KeyFactory');
  var KeyInfo = Java.use('android.security.keystore.KeyInfo');
  var ks = KS.getInstance('AndroidKeyStore'); ks.load(null);
  var aliases = ks.aliases();
  while (aliases.hasMoreElements()) {
    var a = aliases.nextElement();
    try {
      var k = ks.getKey(a, null);
      var info = Java.cast(KF.getInstance(k.getAlgorithm(), 'AndroidKeyStore')
                             .getKeySpec(k, KeyInfo.class), KeyInfo);
      console.log(a,
        '| secureHW=' + info.isInsideSecureHardware(),
        '| userAuthRequired=' + info.isUserAuthenticationRequired(),
        '| authHWEnforced=' + info.isUserAuthenticationRequirementEnforcedBySecureHardware(),
        '| authTimeout=' + info.getUserAuthenticationValidityDurationSeconds());
    } catch (e) { console.log(a, 'ERR', e); }
  }
});
```

On API 31+, `KeyInfo.getSecurityLevel()` returns the level explicitly. The properties that turn a "protected"
key into an unprotected one:

- **`setUserAuthenticationRequired(false)`** — the key is usable by anything in the app's UID, including
  attacker code that reached the process or an IPC surface that performs the operation on request.
- **`setUserAuthenticationParameters(duration, type)` with a non-zero duration** — the key is usable by
  *anything* in the UID for that window after any qualifying unlock. Apps that describe this as "you must
  authenticate each time" are over-claiming; authenticate once and replay the operation from Frida with
  timestamps.
- **`setInvalidatedByBiometricEnrollment(false)`** — biometric-bound keys are invalidated on new enrolment by
  default. Turning that off means an attacker with brief access to an unlocked device enrols their own
  fingerprint and then uses the victim's key.
- **`setUnlockedDeviceRequired` absent** — the key works while the screen is locked, so a background service,
  an exported entry point or a push can drive it.
- **`setIsStrongBoxBacked(true)` with a silent fallback** — it throws `StrongBoxUnavailableException` on
  devices without StrongBox, and the catch block very often falls back to a software key while the UI keeps
  claiming hardware protection. Probe the feature first:
  `adb shell pm list features | grep strongbox`.

### The architectural point AOSP itself makes about key abuse

> "Only storing and using keys in TEE or TRH does not completely solve the problem… if an attacker gains
> access to the low-level interfaces for communicating directly with KeyMint or StrongBox, they can use it as
> an oracle for cryptographic operations that require the private key."

Which is why keys can be authentication-bound and require user presence — and why this is a *testable
application* finding, not a platform observation. Find every path that performs a Keystore operation on
caller-supplied input:

```bash
grep -Rn -B10 'Cipher.getInstance\|Signature.getInstance' out/sources/ \
  | grep -nE 'onReceive|onBind|onStartCommand|@JavascriptInterface|onCreate\(Bundle'
```

An exported surface that takes attacker ciphertext and returns plaintext, or takes attacker bytes and returns
a signature under the app's key, is **Critical**: the key material is perfectly protected and the capability
is completely delegated.

### Attestation

Key attestation produces a certificate chain in which the leaf carries a `KeyDescription` extension, OID
`1.3.6.1.4.1.11129.2.1.17`, containing `attestationSecurityLevel` (`Software` / `TrustedEnvironment` /
`StrongBox`), the `attestationChallenge`, the key's authorisation lists, and a `RootOfTrust` structure with
`verifiedBootKey`, `deviceLocked`, `verifiedBootState` (`Verified`, `SelfSigned`, `Unverified`, `Failed`) and
`verifiedBootHash`. From Android 10 with AVB2 the VBMeta digest is included, supporting firmware transparency.

Five verification rules, each of which is a finding when broken:

1. **Verify on a separate server, not on the device.** An attestation parsed by the client and reported as a
   boolean is worthless: a compromised OS controls the checker. Intercept the submission — if the client sends
   `{"hardwareBacked": true}` rather than the DER chain, flip the boolean and watch the server accept it.
2. **Chain to a Google attestation root** (roots at `android.googleapis.com/attestation/root`), and check
   every certificate against the revocation list at `android.googleapis.com/attestation/status`. Note that
   pre-2021 expired factory keys remain trustworthy unless revoked.
3. **Read the extension from the first occurrence, nearest the root.** Extensions in the leaf may have been
   added by an attacker. A server that parses the leaf's extension can be fed arbitrary claims by anyone who
   can mint a leaf — a complete bypass of hardware attestation.
4. **Bind the challenge to a fresh, single-use, server-issued nonce.** A constant or client-generated
   `attestationChallenge` means one genuine attestation can be replayed forever, from any device or an
   emulator.
5. **Gate on `deviceLocked` / `verifiedBootState` when they are present.** An attestation from a
   bootloader-unlocked device, accepted for a high-value action, is the case the control existed to catch.

### The emulator artefacts that must never be reported

This is a standing rule, not a caveat. On a standard AVD the Keystore is software-backed and the attestation
chain terminates in the **Android Keystore Software Attestation Root**, not the hardware root. Therefore:

| Observation | On an emulator it means |
|---|---|
| `isInsideSecureHardware() == false` | Nothing about the app. |
| `getSecurityLevel()` = software | Nothing about the app. |
| `attestationSecurityLevel: Software` | Nothing about the app. |
| `StrongBoxUnavailableException` | Nothing about the app. |
| `MEETS_VIRTUAL_INTEGRITY` from Play Integrity | Nothing about the app. |
| "root detection bypassed" | Nothing about the app. |

```bash
adb shell getprop ro.kernel.qemu; adb shell getprop ro.hardware; adb shell getprop ro.product.model
adb shell pm list features | grep -iE 'strongbox|hardware_keystore'   # strongbox absent on a stock AVD
```

Re-run **every** key-property, attestation, StrongBox, biometric-class and Play Integrity claim on physical
hardware before it enters a report, and keep two device rows in the evidence section (the instrumentation
device and the stock device, each with model, Android version and patch level). Reporting an emulator-only key
observation as a device finding is the most common way a mobile report is closed as informative.

---

## Scoped storage and MediaStore

### The three zones

| Zone | Path | Protected by | Reachable by |
|---|---|---|---|
| Private internal, credential-encrypted | `/data/user/0/<pkg>` | UID + SELinux categories; CE key | The app; `run-as` if debuggable; a same-UID sibling; backup |
| Private internal, device-encrypted | `/data/user_de/0/<pkg>` | UID + SELinux categories; DE key | Same, **plus the system before first unlock** |
| App-specific external | `/sdcard/Android/data/<pkg>` | Path convention and (from Android 11) platform blocking | The app; blocked cross-app from Android 11, including via SAF |
| Shared collections | MediaStore / SAF | Media permissions, URI grants | Any app with the relevant media permission or grant |

`/sdcard/Android/media/<pkg>` remains comparatively wide, and `MANAGE_EXTERNAL_STORAGE` (an app-op special
permission with Play distribution restrictions) reopens everything.

**CE versus DE is a lockscreen-boundary question, not a path preference.** Data in DE storage is readable by
the system before the user ever unlocks; only CE is protected until authentication. An app that puts secrets in
DE — usually so a `android:directBootAware="true"` component can work during Direct Boot — has moved them
outside the FBE guarantee that a screen-locked stolen device yields no app data.

```bash
grep -RnE 'createDeviceProtectedStorageContext\(|isDeviceProtectedStorage\(' out/sources/
grep -n 'android:directBootAware' out/AndroidManifest.xml
adb shell run-as com.target.app ls -la /data/user_de/0/com.target.app/    # DE
adb shell run-as com.target.app ls -la /data/user/0/com.target.app/       # CE
```

### The version gates that decide whether a claim is live

- **Android 10 / targetSdk 29** — scoped storage by default; `requestLegacyExternalStorage` is the opt-out,
  honoured **only** at targetSdk 29.
- **Android 11 / targetSdk 30** — the opt-out is ignored; cross-app `Android/data` and `Android/obb` access is
  blocked, including through SAF; `WRITE_EXTERNAL_STORAGE` grants no additional access.
  `preserveLegacyExternalStorage` preserves legacy behaviour across an *upgrade* only, never a fresh install.
- **Android 13** — granular `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` / `READ_MEDIA_AUDIO`.
- **Android 14** — `READ_MEDIA_VISUAL_USER_SELECTED` (partial access). An app that does not declare it at
  targetSdk 34 runs in compatibility mode, which is worth confirming rather than assuming.

So "another app can read the target's `Android/data` files" is a real High on Android 10 and below and a
non-finding on 11 and above. State `ro.build.version.sdk` next to the claim, always.

### MediaStore as a two-way surface

**Outbound (what the app leaks).** `MediaStore.MediaColumns.DATA` (`_data`) is an absolute filesystem path.
Returning it to a caller or logging it discloses paths inside other apps' storage, and the documented guidance
is blunt: to create or update a media file, *do not* use the value of `DATA`, because the path is neither
guaranteed valid nor stable. Android 14 additionally redacts `OWNER_PACKAGE_NAME` for apps the caller cannot
see — a provenance check built on it now fails open rather than closed. Android 16 makes `MediaStore.getVersion()`
per-app, which breaks fingerprinting code that assumed a device-wide value.

**Inbound (what the app trusts).** Three distinct primitives, and all three are under-tested:

1. **Attacker-controlled `RELATIVE_PATH` / `DISPLAY_NAME` on insert.** If the app inserts using a filename or
   subdirectory derived from remote or IPC-supplied data, the attacker chooses where the file lands and what
   it is called — including extensions other apps auto-handle. It escalates when the same app, or a sibling,
   reads it back by name.
2. **`OpenableColumns.DISPLAY_NAME` used as a destination filename** — the "dirty stream". A malicious
   provider returning `../../databases/app.db` makes the consuming app overwrite its own files. Note that
   Android 14's `ZipPathValidator` covers the *archive* variant only; it does nothing for provider filenames.
3. **TOCTOU and symlinks on `file://` URIs and passed FDs.** Google's own ContentResolver guidance names both
   symlinks targeting app-internal files and "race conditions exploiting timing between security checks and
   file usage", and specifies the correct algorithm: canonicalise, `fstat()` the **descriptor**, `lstat()` the
   canonical path, detect a remaining symlink, compare inode and device, and block `/proc/` and `/data/misc/`.
   Any code that validates a path *string* and opens it later is racy. And "we target 30, so `file://` cannot
   reach us" is false — `FileUriExposedException` is enforced against the **sender**, who can disable it with
   `StrictMode.setVmPolicy(StrictMode.VmPolicy.LAX)`.

### Grant lifetimes

The Photo Picker (`PickVisualMedia`) grants access until the device restarts or the app stops, and the grant
is persistable with `takePersistableUriPermission()` — with a documented ceiling of **5,000** media grants,
after which the system silently removes the first grant on the list. That ceiling is an availability bug
waiting to happen in any app that hoards grants. SAF's `ACTION_OPEN_DOCUMENT_TREE` is stronger still: a
persisted tree grant is a durable, user-invisible read/write handle over an entire directory that survives
reboot.

```bash
adb shell dumpsys activity permissions | sed -n '/Granted Uri Permissions/,/^$/p'
grep -RnE 'ACTION_OPEN_DOCUMENT_TREE|takePersistableUriPermission|PickVisualMedia' out/sources/
```

---

## App component semantics and intent resolution

### The resolution algorithm

An **explicit** intent names a component and skips resolution entirely — except where Android 13's matching
enforcement or Android 16's `enforceIntentFilter` intervene (below). An **implicit** intent is tested against
every filter of every visible component in three stages, and it must pass all three:

1. **Action.** The filter must list the intent's action, or the intent must carry none and the filter must
   list at least one.
2. **Category.** *Every* category in the intent must appear in the filter. `android.intent.category.DEFAULT`
   is required for an implicit activity start — an activity filter without it is unreachable implicitly.
   `BROWSABLE` is required for a browser to hand a link to the app.
3. **Data.** Scheme first, then host and port, then the path attributes. Two documented rules bite constantly:
   *if no `scheme` is specified, all other URI attributes are ignored*; and *if no `host` is specified, the
   port and all path attributes are ignored*.

And the cross-product rule that produces genuine surprises:

> "All the `<data>` elements contained within the same `<intent-filter>` element contribute to the same
> filter."

So `<data scheme="https"/><data host="a.com"/><data host="b.com"/><data path="/x"/>` yields **both**
`https://a.com/x` and `https://b.com/x`. Developers who wrote two logically separate rules inside one filter
have created combinations they never intended — most dangerously a stray `<data scheme="http"/>` combining
with an otherwise-HTTPS-only host.

### `pathPattern` is not a regular expression

Documented semantics, and they are strange enough to memorise:

- `.` matches any single character.
- `*` matches zero or more of the **immediately preceding** character, and is **greedy**.
- `.*` matches any sequence and is **lazy**.
- There is **no backtracking** — a single forward pass.
- Backslashes must be double-escaped in XML (`\\.` for a literal dot).

Documented non-matches: `"abc.*xyz"` does **not** match `"abcpxqrxyz"`; `"a.*.c"` does **not** match
`"abbbc"`; `"a*a"` does **not** match `"aaa"`. The result is that developers routinely write a pattern that
matches more or less than intended, and the fuzz is cheap:

```bash
for p in "/pay/123" "/pay/../admin" "/pay/123/../../admin" "/PAY/123" "/pay/123%2F..%2Fadmin" "/paysomething"; do
  echo "== $p"; adb shell am start -W -a android.intent.action.VIEW -d "https://example.com$p" com.target.app
done
```

`pathSuffix` and `pathAdvancedPattern` are API 31+; `<data android:query*>` and `android:fragment*` matchers
are API 35+ — an app using the newer matchers has a *narrower* filter on older devices, which is itself a
behavioural split worth testing on both.

Host rules: `scheme`, `host` and `mimeType` are **case-sensitive and must be lowercase** (unlike the RFCs).
A `*` in `host` matches zero or more characters and **must be the first character** — `*.google.com` is valid
and also matches the bare `.google.com`; `google.co.*` is invalid. A wildcard host that admits an unmanaged
subdomain is a subdomain-takeover target wired directly into the app.

### Priority, and why a "high-priority hijack" silently fails

`android:priority` is **capped to 0** when a non-privileged application requests any priority above 0, and
also when a privileged application requests a priority above 0 for `ACTION_VIEW`, `ACTION_SEND`,
`ACTION_SENDTO` or `ACTION_SEND_MULTIPLE`. A third-party hijack app therefore never wins by priority. It wins
by being the *only* handler, by the chooser, or by a user default. `android:order` (API 28+) disambiguates
only *within* one app. Report the hijack path that actually works:

```bash
adb shell cmd package resolve-activity --brief -a android.intent.action.VIEW -d "https://example.com/x"
```

For ordered **broadcasts**, Android 16 confines priority to a single application process; cross-process
delivery order is no longer guaranteed and values are clamped to `SYSTEM_LOW_PRIORITY + 1` …
`SYSTEM_HIGH_PRIORITY - 1`. An app whose security model relies on "we receive it first and abort" is broken on
current devices — which is both a finding against the app and a reason your own interception PoC may fail on
16 and succeed on 15.

### `BROWSABLE`, App Links and verification state

`autoVerify="true"` only *requests* verification. It requires the filter to carry `ACTION_VIEW`, both
`BROWSABLE` **and** `DEFAULT`, and an `http`/`https` scheme; the statement file must sit at
`https://<host>/.well-known/assetlinks.json`, served over HTTPS **with no redirects**. Verification state
lives on the device:

```bash
adb shell pm get-app-links com.target.app
adb shell pm verify-app-links --re-verify com.target.app
curl -sIL https://example.com/.well-known/assetlinks.json     # look for 3xx hops
curl -s  https://example.com/.well-known/assetlinks.json | jq .
apksigner verify --print-certs base.apk | awk '/SHA-256 digest/{print $NF}'
```

Documented states: `none`, `verified`, `approved`, `denied`, `migrated`, `restored`, `legacy_failure`,
`system_configured`, and numeric codes `1024`+ for device-verifier errors. The common real-world failures are a
fingerprint that is the *upload* key rather than the Play App Signing key, only one of several signing certs
listed, a redirect on the statement file, or confusion between the two relation strings
(`delegate_permission/common.handle_all_urls` for link handling versus
`delegate_permission/common.get_login_creds` for credential sharing).

On Android 15+ the system re-verifies periodically in the background and a corrected `assetlinks.json` "can
take up to 7 days to propagate"; on Android 14 and lower there is no periodic re-verification, so a fix only
takes effect on install or update. Put that in the remediation-verification section of the report, because the
client will otherwise report your finding as unfixed.

**Custom schemes have no ownership proof at all.** Any app may register `myapp://`. A magic link, an OAuth
callback or a password-reset token delivered over a custom scheme is interceptable by any installed app, and
that is the shape behind a large fraction of mobile account takeovers.

### `enforceIntentFilter` and the Android 13 matching rules

Android 13 (API 33): if the *sending* app targets 33+, it can only reach another app's component when the
intent matches an `<intent-filter>` in that component — otherwise `ActivityNotFoundException`. The
**exemptions are the bypasses**, and you must test them rather than assume enforcement: components declaring
**no** intent filters; intents originating within the same app; intents from the system UID (1000, including
apps with `android:sharedUserId="android.uid.system"`); and intents from root. That exemption list is precisely
why a PoC run from `adb root` proves nothing about a third-party attacker.

Android 16 (API 36) adds `android:intentMatchingFlags` with values `none`, `enforceIntentFilter` and
`allowNullAction`, settable on `<application>`, `<activity>`, `<activity-alias>`, `<receiver>`, `<service>` and
`<provider>`, where the component value overrides the application value. `enforceIntentFilter` makes cross-app
**explicit** intents match the target's filter and rejects action-less intents. The pattern to hunt is the
hole-punch: `enforceIntentFilter` on `<application>` and `intentMatchingFlags="none"` on one exported
component.

```bash
grep -nE 'intentMatchingFlags' out/AndroidManifest.xml
adb logcat | grep -E "Intent does not match component's intent filter:|Access blocked:"
```

### Export defaults, and the attributes that quietly undo them

| Component | Default `android:exported` |
|---|---|
| `<provider>` | `true` on API 16 and lower; `false` for targetSdk ≥ 17 |
| `<activity>`, `<activity-alias>`, `<service>`, `<receiver>` | `false` with no intent filter; **`true` with at least one** |
| Any of the above, targetSdk ≥ 31 | The attribute is **mandatory**; the build fails without it |

Three attributes routinely undo the developer's intent:

- **`<activity-alias>` inherits nothing.** With the sole exception of `targetActivity`, none of the target's
  attribute values carry over, and the alias's `android:permission` *supplants* the target's. An alias can be
  exported and unguarded while its target is neither. Launch the alias name, not the target name.
- **`android:permission` on `<application>` is a default, not a floor.** For services and receivers it applies
  only where the component sets none; a component that sets its own weaker permission **overrides** rather
  than adds.
- **`android:process`** with a value not beginning with `:` is a *global* process name. Components from
  different apps that share a global process name, the same UID and the same signing certificate share an
  address space.

Two modern activity attributes belong in the same audit: `android:allowEmbedded` (default `false`) with
`android:knownActivityEmbeddingCerts` pinning permitted hosts, and
**`android:requireContentUriPermissionFromCaller`** — values `none` (default), `read`, `write`, `readOrWrite`,
`readAndWrite` — enforced over `Intent.getData()`, `Intent.EXTRA_STREAM` and `Intent.getClipData()`. An
activity that opens a caller-supplied `content://` URI without it accepts URIs the caller never had rights to,
which is the confused-deputy content read in its purest form.

### `PendingIntent` mutability, identity and lifetime

The class javadoc states the threat model itself: "By giving a PendingIntent to another application, you are
granting it the right to perform the operation you have specified **as if the other application was yourself**
(with the same permissions and identity)."

| Property | Semantics | Consequence |
|---|---|---|
| Identity | `Intent.filterEquals()` **plus** `requestCode`. Extras are **not** part of identity. | Two "different" PendingIntents that differ only in extras are the same object. |
| `FLAG_UPDATE_CURRENT` | Rewrites the extras of every outstanding copy — and still works when `FLAG_IMMUTABLE` is set. | A later, lower-privileged creation path silently rewrites an earlier, higher-privileged one. Reply to conversation A lands in conversation B. |
| `FLAG_MUTABLE` | The holder may `fillIn()` unset fields. | With an implicit or under-specified base intent, the holder retargets it and acts as you. |
| `FLAG_ONE_SHOT` | Cancelled automatically after the first `send()`. | Its **absence** on a payment or verification action is replay. |
| `getCreatorPackage()` / `getCreatorUid()` | The creator. | Never the sender. |

Platform guards to check before claiming exploitability: at targetSdk 31+ omitting both mutability flags throws
`IllegalArgumentException`; at targetSdk 34+ the `BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT` change (id
`236704164`) blocks a mutable PendingIntent wrapping an implicit intent, with `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`
as the documented opt-out — grep for it, because its presence is a finding on its own. From Android 15, force-stop
cancels **all** of an app's pending intents, and PendingIntent creators block background activity launches by
default; the first of those is also a methodology trap, so never force-stop between PoC setup and trigger.

### Redirection: the four shapes

1. **Nested intent in an extra.** `getParcelableExtra("key")` cast to `Intent` and passed to
   `startActivity`/`startService`/`sendBroadcast`. The forwarded intent executes with the target's UID and
   carries the target's URI grants.
2. **`setSelector()`.** An `Intent` carries a *selector* intent, and when present the selector — not the
   intent's own action and data — chooses the component. A sanitiser that clears `getComponent()`,
   `getPackage()` and the data URI but never calls `setSelector(null)` is still redirectable.
3. **Surviving `FLAG_GRANT_*`.** If `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`,
   `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` or `FLAG_GRANT_PREFIX_URI_PERMISSION` are not stripped before the
   forward, the victim *grants* rights over its own providers — and `PERSISTABLE` survives reboot.
   `dumpsys activity permissions` will list the grant to your package.
4. **`Intent.parseUri()`.** With `URI_INTENT_SCHEME`, `URI_ANDROID_APP_SCHEME` or `URI_ALLOW_UNSAFE`, it
   rebuilds a full intent — component, action, flags and extras — from an attacker string such as
   `intent://x/#Intent;scheme=https;package=PKG;component=PKG/PKG.internal.NonExportedActivity;end`.

The platform-recommended mitigation is AndroidX `IntentSanitizer` with an explicit component allowlist; its
absence on a forwarding path is the structural finding, and `StrictMode.detectUnsafeIntentLaunch()` (API 31+)
is a cheap way to *locate* the forward before you weaponise it. Android 16 hardens redirection by default, with
`Intent.removeLaunchSecurityProtection()` as the opt-out — grep for it, including the reflective form used for
API ≤ 35 compatibility.

### Tasks and the back stack

- **`taskAffinity`** defaults to the package name. An activity declaring another package's affinity, with
  `allowTaskReparenting="true"`, can be reparented into that task — StrandHogg. StrandHogg 2.0 is not
  preventable by app configuration alone; it needed the Android 11 platform patch, so on API 30+ report only
  residual hygiene (a missing `taskAffinity=""` on credential screens) unless you can demonstrate impact.
- **`launchMode="singleTask"` / `singleTop` / `singleInstance` / `singleInstancePerTask`** reuse an existing
  instance and deliver the new intent to `onNewIntent()`. If security state was established in `onCreate()`
  and `onNewIntent()` re-reads attacker-controlled extras, you can re-drive an already-authenticated screen
  with new parameters — a BOLA expressed in UI form.
- **`FLAG_ACTIVITY_NEW_TASK`** with a matching affinity brings an *existing* task to the foreground and
  restores its state, so an attacker can resurface a mid-flow authenticated screen rather than starting fresh.
  Combine with an overlay and the confirmation is harvested.
- **`documentLaunchMode`** / `FLAG_ACTIVITY_NEW_DOCUMENT` create a task per document, each with its own
  Recents entry and its own snapshot (`/data/system_ce/0/snapshots/`). `excludeFromRecents`,
  `autoRemoveFromRecents` and `noHistory` are the controls; `FLAG_SECURE` is the real one.
- **Overlays.** Android 12 blocks full-occlusion touch passthrough by default — but only for layers with
  opacity **≥ 0.8**, so a 0.7-alpha overlay still works. Partial occlusion (cover the amount, leave the
  Confirm button clear) does not trip `filterTouchesWhenObscured` at all; only a manual
  `MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED` check detects it, and `Window.setHideOverlayWindows(true)`
  (API 31+) is the modern mitigation whose absence on a transaction screen is the finding.

---

## Version-gated classes: a reference table

Establish the triplet before anything else, and quote it beside every version-dependent claim:

```bash
aapt2 dump badging app.apk | grep -E 'sdkVersion|targetSdkVersion|compileSdkVersion|package:'
adb shell dumpsys package com.target.app | grep -E 'versionName|minSdk|targetSdk'
adb shell getprop ro.build.version.sdk ro.build.version.release ro.build.version.security_patch
adb shell getprop | grep build.version.extensions        # SDK Extensions: modern APIs on older OS
```

`Gate` says **what** the behaviour keys on: `target` = the app's `targetSdkVersion`, `min` = its
`minSdkVersion`, `device` = the OS version of the handset under test. Getting the gate type wrong is how a
real finding becomes a retraction.

| API | Gate | What changed | Opens (+) / closes (−) |
|---|---|---|---|
| ≤ 16 | target | `<provider>` exported by default | **+** provider reachable with no intent filter (`D07`) |
| < 17 | min | `addJavascriptInterface` exposes **all** public methods reflectively | **+** generic reflection RCE in WebView (`D10`) |
| 17 | target | Provider default export becomes `false` | **−** the above (`D07`) |
| 18 | target | `FileUriExposedException` when sharing `file://` | **−** partly; the **sender** can disable it with `StrictMode.VmPolicy.LAX` (`D07`) |
| 23 | device | Runtime permission model; `signatureOrSystem` deprecated | **+** app-op/foreground bug classes (`D03`) |
| 23 | device | App Links `autoVerify` available | **−** deep-link hijack where verification succeeds (`D09`) |
| < 24 | target | User-installed CAs trusted by default | **+** MitM with no root, on a stock device (`D14`) |
| 24 | target | App home dir `0751` → `0700`; `dlopen()` restricted to the public-library allowlist | **−** cross-app traversal (`D11`), unrestricted native loads (`D16`) |
| 24 | device | File-Based Encryption with the CE/DE split; key attestation (Keymaster 2) | **+** DE-storage placement class (`D11`), attestation class (`D12`) |
| 24 | device | `setInvalidatedByBiometricEnrollment` | **+** enrolled-finger escalation when set `false` (`D12`) |
| 26 | device | seccomp-bpf for all apps; WebView renderer isolated; multiple binder contexts (Treble); manifest receivers stop getting most implicit broadcasts | **−** silent manifest-receiver surface (`D05`); **+** vendor-binder scoping questions (`D25`) |
| < 28 | target | Cleartext HTTP allowed by default; `MODE_WORLD_*` permitted | **+** cleartext exfil (`D14`), world-readable files (`D11`) |
| 28 | target | Per-app SELinux sandbox mandatory (on Android 9+) | **−** generic cross-app file claims (`D11`) |
| 28 | device | APK Signature Scheme v3 key rotation; `setUnlockedDeviceRequired`; E2E-encrypted cloud backup; privapp-permission violations block boot | **+** rotation-lineage signature checks (`D02`); **−** locked-device key use (`D12`) |
| 28 | device | StrongBox | **+** silent software fallback class (`D12`) |
| 29 | device | Scoped storage; location tri-state; clipboard limited to the focused app / IME; activity starts need a visible window; APEX; `com.android.resolv`; `ObjectInputFilter`; `sharedUserId` deprecated | **−** background clipboard read, background activity pop (`D04`, `D11`, `D20`) |
| 29 | target | `requestLegacyExternalStorage` honoured — **only** at 29 | **+** legacy shared-storage access (`D11`) |
| 29 | device | CVE-2019-2200: custom-permission uninstall variant fixed | **−** that variant only; **orphans remain exploitable on every release** (`D03`) |
| 30 | target | Package-visibility filtering; `setAllowFileAccess` default `false` | **−** free installed-app enumeration (`D01`), `file://` WebView reads (`D10`) |
| 30 | device | Legacy external-storage opt-out ignored; cross-app `Android/data` and `Android/obb` blocked (incl. SAF); one-time permissions; camera/mic foreground-only; StrandHogg 2.0 patched | **−** cross-app app-data reads (`D11`), StrandHogg v2 (`D04`) |
| 30 | device | `RoleManager` roles (Android 10+), `ACCESS_BACKGROUND_LOCATION` semantics | **+** role-protected permission acquisition (`D03`) |
| 31 | target | `android:exported` **mandatory** with an intent filter; PendingIntent mutability mandate; `<uses-native-library>` required; `dataExtractionRules` | **−** accidental export (`D04`–`D07`); **+** deliberate export is now a stronger finding |
| 31 | device | `knownSigner` protection level; `PROTECTION_INTERNAL`; untrusted-touch blocking (≥ 0.8 opacity only); notification trampolines blocked; `detectUnsafeIntentLaunch()`; `setHideOverlayWindows`; ART becomes a Mainline APEX | **+** `knownCerts` allowlist abuse (`D02`), sub-0.8 tapjacking (`D04`), trampoline-fix-introduced mutable PIs (`D08`) |
| 33 | device | Typed `getParcelableExtra(String, Class<T>)` / `readParcelable(ClassLoader, Class<T>)`; `ClipDescription.EXTRA_IS_SENSITIVE`; APK signature scheme v3.1 default for rotation; `sharedUserMaxSdkVersion` | **−** Parcelable type confusion where the typed API is used (`D17`) |
| 33 | target (of the **sender**) | Cross-app intents must match the target's filter — exemptions: filterless components, same app, system UID (1000), root | **−** mismatched-intent delivery (`D04`–`D06`); **note the adb/root exemption when writing PoCs** |
| 34 | target | Implicit intents reach only exported components; `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` mandatory; DCL files read-only **before** write; `ZipPathValidator`; mutable PendingIntent without component/package throws; MediaProjection per-session consent; BAL opt-in modes; foreground-service type mandate | **−** implicit-to-internal dispatch (`D08`), default-exported runtime receivers (`D05`), zip traversal (`D17`); **+** the `setReadOnly()`-ordering race becomes the specific finding |
| 34 | device | Conscrypt APEX holds the live trust store; `READ_MEDIA_VISUAL_USER_SELECTED`; `OWNER_PACKAGE_NAME` redaction; `BroadcastReceiver.getSentFromUid()`/`getSentFromPackage()`; minimum installable targetSdk 23 | **−** `/system` cacerts inspection as a control (`D14`); **+** provenance checks failing open (`D07`) |
| 35 | target | TLS 1.0/1.1 disallowed **via Conscrypt**; PendingIntent creators block BAL by default | **−** obsolete TLS for platform-stack apps; **+** bundled-TLS-stack apps unaffected (`D14`, `D19`) |
| 35 | device | Force-stop cancels all PendingIntents; OTP redaction from untrusted `NotificationListenerService`; screenshare protections; signature-permission allowlist for platform-signed non-system apps; Private Space; periodic App Links re-verification; minimum installable targetSdk 24 (`--bypass-low-target-sdk-block`) | **−** OTP siphoning via listeners (`D13`), widget/alarm persistence assumptions (`D08`) |
| 36 | device | Intent-redirection hardening **on by default**, opt-out `Intent.removeLaunchSecurityProtection()`; ordered-broadcast priority confined to one process and clamped; local network permission (`NEARBY_WIFI_DEVICES`); `MediaStore.getVersion()` per-app; ART updated via Play system updates | **−** default redirection (`D08`), cross-process abort-on-receive (`D05`); **+** the opt-out call is itself a finding |
| 36 | target | `android:intentMatchingFlags` (`none` / `enforceIntentFilter` / `allowNullAction`); orientation and aspect-ratio locks ignored on large screens | **−** action-less explicit intents where `enforceIntentFilter` is set; **+** the per-component `"none"` hole-punch (`D04`–`D06`) |
| — | device | 16 KB page-size devices reject 4 KB-aligned `.so` files; `android:pageSizeCompat` | **+** runtime download of a "corrected" library as a DCL path (`D17`) |

A quick gate script, because the `LEGACY` lines are what decide half the report:

```bash
T=$(aapt2 dump badging app.apk | grep -oE "targetSdkVersion:'[0-9]+'" | grep -oE '[0-9]+')
echo "targetSdk=$T"
[ "$T" -lt 24 ] && echo "LEGACY: user CAs trusted by default; home dir 0751"
[ "$T" -lt 28 ] && echo "LEGACY: cleartext allowed; world-accessible file modes permitted"
[ "$T" -lt 30 ] && echo "LEGACY: can enumerate all packages; WebView file access on by default"
[ "$T" -lt 31 ] && echo "LEGACY: implicit export by intent filter; PendingIntent mutability unmandated"
[ "$T" -lt 34 ] && echo "LEGACY: implicit intents reach internal components; receivers export by default; DCL may be writable; zip traversal unvalidated"
[ "$T" -lt 35 ] && echo "LEGACY: platform does not enforce TLS >= 1.2 for this app"
```

---

## How to find something novel from the architecture

The checklist is the floor. Everything below is how you get above it. All three moves start from the same
place — the organising principle at the top of this document — and all three end in the same place: a named
boundary crossing with an observable.

### Move 1 — cross two surfaces nobody reviews together

Checklists are organised by *component type*, and so are reviewers' attention spans. The findings that survive
are at the joins, because the join has no owner. The method: take two surfaces from different chapters, write
down what each hands to the other, and ask what the receiving side assumes.

**Worked example — notification access × PendingIntent authorisation.** A `NotificationListenerService` can
read every notification on the device, including `contentIntent` and each action's `actionIntent`. Those are
live `PendingIntent`s created by other apps. Separately, some apps that *receive* a `PendingIntent` decide
whether to honour it by calling `getCreatorPackage()`. Nobody reviews notification access and PendingIntent
authorisation in the same pass, because they are in different chapters. Join them and the attack writes
itself: obtain a legitimately-created PendingIntent from the notification stream, `send()` it, and the
receiver's creator check authenticates the *victim* while the sender is you. The documented impact runs to
authentication bypass and privilege escalation, and the receiver-side fix (`getSentFromUid()`) only exists
from API 34 and only when the sender opted in — which is why the pattern persists.

**Worked example — backup/restore × the control plane.** Everyone asks "is my token in the backup set?".
Almost nobody asks the inverse: **which restored value does the app trust on next launch?** Restore happens
after APK installation and **before the user can launch the app**, so an attacker-authored API base URL, host
map, remote-config cache, certificate-pin set, "device trusted" flag or kill-switch state is live before the
app's first packet. An app that pins perfectly is fully MitM-able if its pin set is a restorable file. The
same join has an asymmetry worth its own test: Android 12+ `dataExtractionRules` splits `<cloud-backup>` from
`<device-transfer>`, and **a missing section means that mode is fully enabled** — so an app that carefully
excludes secrets from cloud backup and omits `<device-transfer>` has no device-transfer restrictions at all.
The D2D path is testable with `bmgr`, and nobody tests it.

**Worked example — `sharedUserId` × `android:process`.** Each is a `D03` checklist row on its own and each is
usually rated Medium. Together — a shared UID, a same-key sibling, and a globally named process — they are
attacker code executing inside the target's own address space with the target's Keystore aliases. The chain
only appears if you read both rows at once.

**Worked example — SP-HALs × an exported import feature.** Vendor graphics and codec code runs *inside* the
app process, and that process holds an open GPU device FD. An exported activity or provider that decodes an
attacker-supplied image, video or shader is therefore a memory-safety surface in the app's UID, adjacent to a
kernel driver handle — not the "app crashes" finding that a tombstone alone suggests.

**Worked example — MediaStore insert × the app's own importer.** Attacker-controlled `RELATIVE_PATH` and
`DISPLAY_NAME` let you choose where a file lands and what it is called. On its own that is content planting,
Medium. Now find the app's import or "restore from folder" feature that reads files back *by name* from that
directory. The join is the finding.

The generalisation, and the question to keep in your notes: **for every capability this app holds, which other
app-reachable surface can make it use that capability on my behalf?** That is the confused deputy stated as a
search strategy rather than a bug class.

### Move 2 — read the mitigation, then find the path that skips it

Every platform mitigation document names its own opt-out, because compatibility demands one. The opt-out is a
`grep`. This is the highest-yield-per-minute technique in Android testing, and it produces findings that are
*self-evidencing*: the developer explicitly disabled a security control, in code, on a reachable path.

| Mitigation | The documented escape | What to grep |
|---|---|---|
| Android 16 intent-redirection hardening | `Intent.removeLaunchSecurityProtection()` | `removeLaunchSecurityProtection`, and `getDeclaredMethod("removeLaunchSecurityProtection")` for the reflective form |
| Android 16 `enforceIntentFilter` | per-component `android:intentMatchingFlags="none"` | `intentMatchingFlags` in the manifest |
| Android 14 zip-path validation | `dalvik.system.ZipPathValidator.clearCallback()` | `ZipPathValidator` |
| Android 14 mutable-implicit PendingIntent block | `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` | `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` |
| Android 14 DCL read-only requirement | writing first and calling `setReadOnly()` afterwards | `setReadOnly` near `FileOutputStream` / `DexClassLoader` |
| Android 15 BAL defaults | `setPendingIntentBackgroundActivityStartMode(MODE_BACKGROUND_ACTIVITY_START_ALLOWED)`, `BIND_ALLOW_ACTIVITY_STARTS` | those constants |
| Android 12 untrusted-touch blocking | it only blocks layers with opacity ≥ 0.8 | build the 0.7-alpha overlay |
| Conscrypt TLS floor (targetSdk 35) | a bundled TLS stack the floor never reaches | `libssl`/`libcrypto` in `lib/`, `libflutter.so`, a BouncyCastle provider at index 0 |
| Android 14 trust store in the APEX | the app's own "detect proxy CA" code reads `/system/etc/security/cacerts` | that path, in `sources/` and `smali/` |
| Scoped storage | `requestLegacyExternalStorage` (targetSdk 29), `MANAGE_EXTERNAL_STORAGE` | those names in the manifest |
| `FileUriExposedException` | the **sender** sets `StrictMode.VmPolicy.LAX` | you control the sender — it is not a defence |
| Minimum installable targetSdk | `adb install --bypass-low-target-sdk-block` | ask the client how they sideload the legacy fleet |

There is a second, subtler form of this move: **read the mitigation and ask what it does *not* cover.**
Android 14's `ZipPathValidator` covers archive entry names; it does nothing for a `DISPLAY_NAME` supplied by a
foreign provider. Android 12's touch blocking covers full occlusion above an opacity threshold; it does
nothing for partial occlusion. The typed `getParcelableExtra` overloads (API 33) prevent *type confusion*;
they do nothing about a byte-count mismatch inside a `Parcelable` the app itself defines. Verified Boot
attests the platform; it attests nothing about an app's own claim. APK signature verification covers the APK;
the code that runs is the `.odex`. In each case the gap is exactly where the next bug lives.

### Move 3 — follow the data, not the API

Checklists enumerate APIs. Attackers enumerate *values*. Pick one value that matters, then trace every place
it comes to rest and every boundary it crosses, and test the crossings rather than the functions.

**Worked example — follow the session token outward.** Where does it come to rest? `shared_prefs` XML; a
SQLite row; the cloud-backup set; the device-transfer set; `logcat`; a crash-reporter breadcrumb; the
clipboard; a `Bundle` in an implicit broadcast; a WebView cookie jar; a Keystore-wrapped blob whose key has
`userAuthRequired=false`; a `ParcelFileDescriptor` returned from a bound service; an FCM payload echo; a
`WorkSpec` input blob in the WorkManager database. That list is thirteen tests, spread across six checklist
domains, all of which fall out of naming one value. Then ask the second question — the one that produces the
High: **which of those resting places is reachable by a principal other than this app's UID, without root?**

**Worked example — follow a trusted value inward.** Take the API base URL. Now enumerate every *writer*: a
`BuildConfig` constant; a remote-config cache in the backup set; a broadcast extra on an exported receiver; a
deep-link query parameter; a debug-menu setting still present in the release build; a restored
`SharedPreferences` file; an app-writable `persist.` system property; a `content://` import. The writer nobody
thought of is the finding, and repointing the base URL is usually Critical because everything downstream
follows it. The same trace works for the pin set, the feature-flag map, the "device trusted" cache and the
kill switch.

**Worked example — follow the bytes through a Parcel.** For every `Parcelable` the app defines, instrument
`writeToParcel` and `CREATOR.createFromParcel` and compare `Parcel.dataPosition()` deltas for the same object.
Unequal deltas are the precondition for the self-changing-`Bundle` primitive; the delivery vehicle is any path
where the app forwards an externally supplied `Bundle` to a more privileged component. This is not exotic —
it is the root cause of CVE-2017-0806, CVE-2021-0748, CVE-2021-0928 and CVE-2023-20963, and the measurement is
about twenty lines of Frida.

**Worked example — follow a filename.** Take `OpenableColumns.DISPLAY_NAME` from a foreign provider and follow
it to the `File` constructor. Take `entry.getName()` from an archive and follow it to `new File(base, name)`.
Take a download's server-supplied filename and follow it to `code_cache/`. In each case, the question is
whether canonicalisation happens between the source and the `open()` — and whether the check was performed on
the **path string** rather than on the **descriptor**, which is the TOCTOU variant.

### The discipline that makes a novel idea reportable

Novelty without rigour is a closed report. Three rules:

1. **Write the refuting experiment before you write the claim.** If you cannot state what result would prove
   the idea wrong, you do not have a hypothesis, you have a hope. Label it `HYPOTHESIS` in your notes until
   the experiment runs, and carry the label into the report if it still has not.
2. **Report the observable, never the technique.** The finding is the returned bytes, the HTTP 200 with the
   victim's profile, the `dumpsys` grant-state diff, the AVC line (or its documented absence), the tombstone,
   the screen recording of a component that `am start` alone could not start. "The app is vulnerable to intent
   redirection" is a sentence; `dumpsys activity activities` showing a non-exported activity resumed is a
   finding.
3. **Prove it from the weakest attacker that still works.** Discovery from `adb shell` is fine and fast; a
   finding proved only from `adb shell` has not established the zero-permission-app model, and a triager will
   say so. Re-run the final PoC from an installed, differently-signed APK that declares no permissions, on a
   device reporting `getenforce` = `Enforcing` and `ro.build.type` = `user`, and commit that manifest as
   evidence.

---

## Related

| | |
|---|---|
| [`docs/02-severity-and-reportability.md`](02-severity-and-reportability.md) | What counts as a finding, and what the VRT pays for |
| [`docs/03-lab-and-harness.md`](03-lab-and-harness.md) | Building the harness this document says you need |
| [`docs/04-poc-and-evidence-standard.md`](04-poc-and-evidence-standard.md) | The evidence bundle each claim ships with |
| [`docs/05-attacker-models.md`](05-attacker-models.md) | AM-01…AM-12, and the rule about reporting the weakest |
| [`docs/06-triage-playbook.md`](06-triage-playbook.md) | Turning a primitive into a payable finding |
| [`docs/07-coverage-crosswalk.md`](07-coverage-crosswalk.md) | D01–D27 mapped to MASVS, MASTG, ATT&CK and the VRT |
| [`docs/09-coverage-discipline.md`](09-coverage-discipline.md) | Breadth before depth, and the P7 gate |
| [`CHECKLIST.md`](../CHECKLIST.md) | The domain index and each domain's crux question |
