# frida/ — runtime scripts

## Quick start — the four things that produced false negatives in real engagements

```bash
export ANDROID_SERIAL=emulator-5554          # 1. DEVICE: never `-U`; with a phone AND an AVD attached, -U picks silently
adb -s "$ANDROID_SERIAL" root                # 2. ROOT: frida-server started from a non-root shell fails silently
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell 'chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'
#   Magisk phone:  adb shell su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'
frida-ps -D "$ANDROID_SERIAL" | head -3      # server answers, on THIS device

# 3. TIMEOUT: -q without -t detaches right after the script loads and every hook shows zero hits
#    (frida-tools 17 removed the old no-pause flag; a spawned app resumes by default, `--pause` keeps it suspended)
# spawn (login-time hooks, RASP-free apps):
frida -D "$ANDROID_SERIAL" -f com.victim.app -l frida/01-webview-settings.js -t 120 -q | tee "$E/logs/frida-01-$(date +%s).log"
# 4. ATTACH (the app is already running, or spawn trips its RASP): foreground it FIRST, then
timeout 120 frida -D "$ANDROID_SERIAL" -n com.victim.app -l frida/01-webview-settings.js    # REPL: rpc.exports.dump()
#    -t is honoured only in spawn mode; `timeout` ends an attach session. Attaching to a cached/FROZEN process
#    (cat /sys/fs/cgroup/uid_<uid>/pid_<pid>/cgroup.freeze == 1) hangs and can SIGSEGV the target: `am start` it first.
```

`send()` events (the machine lines: `{script, ev, tag:"CANDIDATE", items:[...]}`) appear as `message:` lines in the
tee'd log; grep them with `grep -o '"ev":.*' $E/logs/frida-*.log`. One Frida session per device: a second worker's
`frida -f`, `am force-stop` or `pm clear` on the same device kills yours — take the device lock (docs/03 §5).

## Three correctness rules that cost people whole engagements

1. **Hooking an abstract framework class records nothing.** Hooks on `android.webkit.WebSettings`
   yield zero calls because the concrete class is `ContentSettingsAdapter` / `AwSettings`; `android.net.Uri.getHost`
   is abstract and the concrete class is `Uri$HierarchicalUri`. Zero hits from a base-class hook is a **false
   negative**, not a clean result. Every script here names the concrete class it hooks and prints
   `[NN][UNVERIFIED] hook X failed` when an install fails, so a silent hook never exists.
2. **Prefer reading state off live objects (`Java.choose`) over intercepting setters.** A setter hook
   only sees calls made while you were attached; `Java.choose` tells you what is true *now*. Scripts 01, 02 and 06
   expose `rpc.exports.dump()` for that; 03, 04 and 05 trace calls and therefore need spawn mode (column below).
3. **A tool's silence is never a negative result.** Only a manifest read or a code read establishes a
   negative. Each script header has a "Zero result means" block; read it before recording any zero.

| Script | Domain | What it answers | Mode | Zero result means |
|---|---|---|---|---|
| `01-webview-settings.js` | D10 | The real WebView settings, read off live objects (loader-aware) | spawn or attach; `dump()` | see its header: UNVERIFIED vs no live WebView vs loads before attach |
| `02-bridge-enum.js` | D10 | Every `@JavascriptInterface` method, rated by return type | spawn (call-time) or attach + `dump()` | 0 in attach without `dump()` = UNVERIFIED; 0 after UI walk + `dump()` + static zero = negative |
| `03-deeplink-trace.js` | D09 | Which component received the URI, how it parsed it, which sink it reached | spawn or attach, then fire the link | no `[SINK]` = nothing launched while attached; confirm from `$DEC` (sink may be `loadUrl`, use 01) |
| `04-crypto-trace.js` | D12 | Cipher/key fingerprint/IV actually used, tied by `Cipher.init`; IV repeat counter | spawn (login-time crypto) | no lines = no `javax.crypto` on that path (native/Tink/Keystore-only); needs the static read |
| `05-keystore-trace.js` | D12/D13 | `KeyGenParameterSpec` as **built**, and whether a prompt carries a `CryptoObject` | spawn after `pm clear` for builders; attach OK for prompts | `[UNVERIFIED] class not found in any loader` = library not loaded, not absent |
| `06-file-trace.js` | D11 | Every file opened (terminal constructors), prefs writes, **live prefs dump** | spawn for writes; attach + `dump()` for state | no `[W]` in attach = expected; the dump and the on-disk read are the truth |

Key material is never printed by default (`04` prints `sha256[0:8]`; `rpc.exports.reveal(true)` for a deliberate
capture into `$E/sensitive/`). Everything a script tags `CANDIDATE` is a candidate, never a finding (docs/04).
