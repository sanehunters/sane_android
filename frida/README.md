# frida/ — runtime scripts

```bash
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
frida -U -f com.victim.app -l frida/01-webview-settings.js
```

## Three correctness rules that cost people whole engagements

1. **Hooking an abstract framework class records nothing.** Hooks on `android.webkit.WebSettings`
   yield zero calls because the concrete class is `ContentSettingsAdapter` / `AwSettings`. Zero hits
   from a base-class hook is a **false negative**, not a clean result.
2. **Prefer reading state off live objects (`Java.choose`) over intercepting setters.** A setter hook
   only sees calls made while you were attached; `Java.choose` tells you what is true *now*.
3. **A tool's silence is never a negative result.** Only a manifest read or a code read establishes a
   negative.

| Script | Domain | What it answers |
|---|---|---|
| `01-webview-settings.js` | D10 | The real WebView settings, read off live objects |
| `02-bridge-enum.js` | D10 | Every `@JavascriptInterface` method, and what each returns |
| `03-deeplink-trace.js` | D09 | Which component received the URI and what it did with it |
| `04-crypto-trace.js` | D12 | Cipher/key/IV actually used at runtime |
| `05-keystore-trace.js` | D12/D13 | `KeyGenParameterSpec` properties as built |
| `06-file-trace.js` | D11 | Every file the app opens after login |
