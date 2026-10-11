/* 01-webview-settings.js — D10: the EFFECTIVE WebView configuration read off live objects, who set it, and what
 * gets loaded through it.
 *
 * Serves   D10-001 (settings on the concrete class), D10-017 (scheme never validated), D10-020 (WebViewClient
 *          allow-list), D10-022/-023 (loadData* with a hostile or null base), D10-025 (javascript: /
 *          evaluateJavascript), D10-029/-030 (multiple windows / onCreateWindow), D10-031/-032/-033 (file:// and
 *          content:// access), D10-037 (onShowFileChooser), D10-039 (onReceivedSslError -> proceed), D10-040
 *          (mixed content), D10-049 (remote debugging), D10-050/-051 (web permission auto-grant), D10-052
 *          (Safe Browsing), D09-059/-060 (deep link -> loadUrl, loadUrl(url, headers)).
 * Maps to  MASTG-TEST-0251, MASTG-TEST-0253, MASTG-TEST-0400, MASTG-TECH-0043, MASTG-DEMO-0030, MASTG-DEMO-0082,
 *          MASTG-DEMO-0158.
 *
 * Mechanism — why it is written this way
 *  - android.webkit.WebSettings is abstract. The concrete class, com.android.webview.chromium.
 *    ContentSettingsAdapter (delegating to org.chromium.android_webview.AwSettings), is loaded by the WebView
 *    PROVIDER's own ClassLoader, not the app's. Java.use()/Java.choose() through the default factory throw
 *    ClassNotFoundException for it. The loader is located with
 *    Java.enumerateMethods('com.android.webview.chromium.*!setJavaScriptEnabled') (MASTG-DEMO-0082) and, as a
 *    fallback, Java.enumerateClassLoadersSync() + loadClass(); a dedicated Java.ClassFactory.get(loader) is used
 *    so the default factory keeps resolving app classes. The provider is loaded only when the first WebView is
 *    constructed, so this runs lazily: from the WebView constructor and getSettings() hooks and from the re-scan
 *    timer — never once at spawn.
 *  - The settings DUMP needs no provider loader: Java.choose('android.webkit.WebView') -> getSettings() -> the
 *    getters is virtual dispatch into the concrete class (MASTG-DEMO-0030). WebView methods assert the UI thread,
 *    hence Java.scheduleOnMainThread.
 *  - Java.choose at spawn finds nothing: no WebView exists yet. The dump re-runs on a timer (CONFIG.rescanMs),
 *    on every WebView construction, and on demand (rpc.exports.dump()); it reports new instances and changed
 *    values only.
 *  - Setter hooks on ContentSettingsAdapter answer what the dump cannot: WHICH code path set a value (backtrace).
 *    Reads tell you what is true now; setter hooks tell you who made it true.
 *  - WebViewClient / WebChromeClient callbacks are hooked on the concrete class the app registers (reflection on
 *    getDeclaredMethods at setWebViewClient time). A hook on the base class only fires when nobody overrides.
 *    SslErrorHandler.proceed(), PermissionRequest.grant() and the geolocation callback are chromium-side
 *    subclasses: they are hooked lazily on the runtime class of the object the callback receives.
 *
 * Run      frida/run.sh --script 01 --pkg <pkg> --timeout 120            (spawn or attach both work; see README)
 *          raw: frida -U -f <pkg> -l frida/01-webview-settings.js  -> exercise the UI -> REPL: rpc.exports.dump()
 *          Exercise every screen that may host a WebView BEFORE reading the result.
 *
 * Output   human lines are prefixed [01]; machine lines go through send() as JSON
 *          {script:"01-webview-settings", ev:<event>, ts, tag:"CANDIDATE"|"", items:[Dnn-NNN...], ...}
 *          and land in $E/logs/frida-01-webview-settings-<ts>.jsonl when started through run.sh.
 *          A CANDIDATE line is a candidate, never a finding: it still needs a delivery path (D10-016+) and the
 *          AM-02 proof from a page (docs/05).
 *
 * Zero result — false negative or clean?
 *  - "[01][UNVERIFIED] ..." = the check could not run (Frida/ART version mismatch, Java.choose unsupported,
 *    provider loader not found). Not tested. Fix the harness (D26) and re-run.
 *  - 0 WebView instances after a FULL UI walk plus rpc.exports.dump() = "no live WebView at that moment". It is a
 *    negative for D10-001 only together with a static negative (no android.webkit/androidx.webkit usage and no
 *    framework WebView in the jadx output).
 *  - 0 load events with instances present = the loads happened before attach; re-run in spawn mode.
 *  - 0 setter events in attach mode is expected (the settings were applied before you attached): the dump is the
 *    truth, setter events are provenance.
 *
 * Tested   syntax with `node --check`; Frida API use follows MASTG-DEMO-0030/0082 (Java.enumerateMethods,
 *          Java.ClassFactory.get, Java.scheduleOnMainThread). Android 14-16 need frida >= 17.1.5 on both sides.
 */
'use strict';

var SCRIPT = '01-webview-settings';
var CONFIG = {
  rescanMs: 5000,       // 0 = no timer; rpc.exports.setrescan(ms) changes it live
  stackFrames: 8,
  maxGetSettingsLogs: 3 // the first N getSettings() callers are logged with a backtrace, then silence
};

// ---------- output -------------------------------------------------------------------------------------------
function emit(ev, fields) {
  var o = { script: SCRIPT, ev: ev, ts: new Date().toISOString(), tag: '', items: [] };
  Object.keys(fields || {}).forEach(function (k) { o[k] = fields[k]; });
  try { send(o); } catch (e) { /* no host listening (frida -q without send handler): console still has it */ }
  return o;
}
function log(s) { console.log('[01]' + s); }
function unverified(why, extra) {
  log('[UNVERIFIED] ' + why);
  var f = extra || {}; f.why = why;
  emit('unverified', f);
}
function backtrace(max) {
  try {
    var s = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new());
    var lines = String(s).split('\n').map(function (l) { return l.trim(); })
      .filter(function (l) { return l.indexOf('at ') === 0; })
      .map(function (l) { return l.substring(3); });
    var isFw = function (l) {
      return /^(java\.|javax\.|android\.|com\.android\.|dalvik\.|org\.chromium\.|kotlin\.|kotlinx\.|androidx\.)/.test(l);
    };
    var app = lines.filter(function (l) { return !isFw(l); });
    return { top: lines.slice(0, max), app: app.slice(0, max) };
  } catch (e) { return { top: [], app: [] }; }
}
function caller(bt) { return bt.app[0] || bt.top[0] || '?'; }
function frames(bt) { return bt.app.length ? bt.app : bt.top; }

// per-thread re-entrancy guard: constructor chains and (WebView,WebResourceRequest)->(WebView,String) delegation
// would otherwise log one call twice
var guards = {};
function guarded(key, fn, nested) {
  var k = key + '#' + Process.getCurrentThreadId();
  if (guards[k]) return nested();
  guards[k] = true;
  try { return fn(); } finally { delete guards[k]; }
}
function str(x) { try { return x === null || x === undefined ? 'null' : String(x); } catch (e) { return '<' + e + '>'; } }
function scheme(u) { var m = /^\s*([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(str(u)); return m ? m[1].toLowerCase() : ''; }

// ---------- the provider ClassLoader (MASTG-DEMO-0082) ---------------------------------------------------------
var provider = null; // { loader, factory, settingsClass, how }
function findProviderLoader() {
  if (provider) return provider;
  var hit = null;
  try {
    var groups = Java.enumerateMethods('com.android.webview.chromium.*!setJavaScriptEnabled');
    if (groups.length > 0 && groups[0].classes.length > 0) {
      hit = { loader: groups[0].loader, settingsClass: groups[0].classes[0].name, how: 'Java.enumerateMethods' };
    }
  } catch (e) { log('[note] Java.enumerateMethods failed: ' + e); }
  if (!hit) {
    var wanted = ['com.android.webview.chromium.ContentSettingsAdapter', 'org.chromium.android_webview.AwSettings'];
    var loaders = [];
    try { loaders = Java.enumerateClassLoadersSync(); } catch (e) { log('[note] Java.enumerateClassLoadersSync failed: ' + e); }
    for (var i = 0; i < loaders.length && !hit; i++) {
      for (var j = 0; j < wanted.length && !hit; j++) {
        try { loaders[i].loadClass(wanted[j]); hit = { loader: loaders[i], settingsClass: wanted[j], how: 'Java.enumerateClassLoadersSync' }; }
        catch (e) { /* not this loader */ }
      }
    }
  }
  if (!hit) return null;
  try { hit.factory = Java.ClassFactory.get(hit.loader); } catch (e) { unverified('Java.ClassFactory.get(providerLoader) failed: ' + e); return null; }
  provider = hit;
  log('[loader] provider loader via ' + hit.how + ' -> ' + hit.settingsClass);
  emit('provider-loader', { how: hit.how, settingsClass: hit.settingsClass, loader: str(hit.loader), items: ['D10-001'] });
  return hit;
}

// name -> { items, candidate(value) }  — all are real android.webkit.WebSettings methods implemented by
// ContentSettingsAdapter; a hook that is absent on this provider is reported, not silently skipped
var SETTERS = {
  setJavaScriptEnabled:                  { items: ['D10-001', 'D10-018'], candidate: function (v) { return false; } },
  setAllowFileAccess:                    { items: ['D10-032'],            candidate: function (v) { return v === true; } },
  setAllowFileAccessFromFileURLs:        { items: ['D10-031'],            candidate: function (v) { return v === true; } },
  setAllowUniversalAccessFromFileURLs:   { items: ['D10-031'],            candidate: function (v) { return v === true; } },
  setAllowContentAccess:                 { items: ['D10-033'],            candidate: function (v) { return false; } },
  setDomStorageEnabled:                  { items: ['D10-047'],            candidate: function (v) { return false; } },
  setMixedContentMode:                   { items: ['D10-040'],            candidate: function (v) { return v === 0; } },
  setSafeBrowsingEnabled:                { items: ['D10-052'],            candidate: function (v) { return v === false; } },
  setJavaScriptCanOpenWindowsAutomatically: { items: ['D10-030'],         candidate: function (v) { return false; } },
  setSupportMultipleWindows:             { items: ['D10-029', 'D10-030'], candidate: function (v) { return false; } },
  setSavePassword:                       { items: ['D10-047'],            candidate: function (v) { return v === true; } },
  setSaveFormData:                       { items: ['D10-047'],            candidate: function (v) { return false; } },
  setGeolocationEnabled:                 { items: ['D10-051'],            candidate: function (v) { return false; } },
  setDatabaseEnabled:                    { items: ['D10-047'],            candidate: function (v) { return false; } },
  setUserAgentString:                    { items: ['D10-001'],            candidate: function (v) { return false; } }
};
var MIXED = { 0: 'MIXED_CONTENT_ALWAYS_ALLOW', 1: 'MIXED_CONTENT_NEVER_ALLOW', 2: 'MIXED_CONTENT_COMPATIBILITY_MODE' };

var providerHooked = false;
function installProviderHooks() {
  if (providerHooked) return true;
  var p = findProviderLoader();
  if (!p) return false;
  var CSA;
  try { CSA = p.factory.use(p.settingsClass); }
  catch (e) { providerHooked = true; unverified('cannot use ' + p.settingsClass + ' through the provider loader: ' + e); return false; }
  var n = 0, missing = [];
  Object.keys(SETTERS).forEach(function (name) {
    var m = CSA[name];
    if (!m) { missing.push(name); return; }
    m.overloads.forEach(function (o) {
      o.implementation = function () {
        var raw = arguments.length ? arguments[0] : undefined;
        var v = str(raw);
        if (name === 'setMixedContentMode') v = v + ' (' + (MIXED[raw] || 'unknown') + ')';
        var bt = backtrace(CONFIG.stackFrames);
        var tag = SETTERS[name].candidate(raw) ? 'CANDIDATE' : '';
        log('[setter]' + (tag ? '[' + tag + ']' : '') + ' ' + name + '(' + v + ') <- ' + caller(bt));
        emit('setter', { method: name, value: v, impl: p.settingsClass, tag: tag, items: SETTERS[name].items, stack: frames(bt) });
        return o.apply(this, arguments);
      };
      n++;
    });
  });
  providerHooked = true;
  log('[hook] ' + n + ' setter overloads on ' + p.settingsClass + (missing.length ? ' (absent on this provider: ' + missing.join(',') + ')' : ''));
  emit('hooks', { target: p.settingsClass, overloads: n, missing: missing, items: ['D10-001'] });
  return true;
}

// ---------- the live dump (MASTG-DEMO-0030) ---------------------------------------------------------------------
var GETTERS = [
  ['javaScriptEnabled', 'getJavaScriptEnabled'],
  ['allowFileAccess', 'getAllowFileAccess'],
  ['allowFileAccessFromFileURLs', 'getAllowFileAccessFromFileURLs'],
  ['allowUniversalAccessFromFileURLs', 'getAllowUniversalAccessFromFileURLs'],
  ['allowContentAccess', 'getAllowContentAccess'],
  ['domStorageEnabled', 'getDomStorageEnabled'],
  ['databaseEnabled', 'getDatabaseEnabled'],
  ['mixedContentMode', 'getMixedContentMode'],
  ['safeBrowsingEnabled', 'getSafeBrowsingEnabled'],
  ['javaScriptCanOpenWindowsAutomatically', 'getJavaScriptCanOpenWindowsAutomatically'],
  ['supportMultipleWindows', 'supportMultipleWindows'],
  ['savePassword', 'getSavePassword'],
  ['saveFormData', 'getSaveFormData'],
  ['cacheMode', 'getCacheMode'],
  ['userAgentString', 'getUserAgentString']
];
var dumping = false;        // our own getSettings() calls must not re-trigger the getSettings hook
var seen = {};              // webview identity -> signature of (settings, url)
var lastCount = -1;

function readSettings(wv) {
  var s = wv.getSettings();
  var out = { impl: s.getClass().getName() };
  GETTERS.forEach(function (g) {
    try { out[g[0]] = str(s[g[1]]()); }
    catch (e) { out[g[0]] = '<unavailable: ' + (e.message || e) + '>'; } // a missing getter is not "false"
  });
  return out;
}
function rate(st) {
  var tags = [];
  var js = st.javaScriptEnabled === 'true';
  if (st.allowUniversalAccessFromFileURLs === 'true') tags.push({ item: 'D10-031', why: 'allowUniversalAccessFromFileURLs=true' });
  if (js && st.allowFileAccessFromFileURLs === 'true') tags.push({ item: 'D10-031', why: 'allowFileAccessFromFileURLs=true with JS on' });
  if (js && st.allowFileAccess === 'true') tags.push({ item: 'D10-032', why: 'allowFileAccess=true with JS on (needs a file:// load path)' });
  if (st.mixedContentMode === '0') tags.push({ item: 'D10-040', why: 'MIXED_CONTENT_ALWAYS_ALLOW' });
  if (st.safeBrowsingEnabled === 'false') tags.push({ item: 'D10-052', why: 'Safe Browsing disabled' });
  if (st.savePassword === 'true') tags.push({ item: 'D10-047', why: 'savePassword=true' });
  return tags;
}
function notes(st) {
  var n = [];
  if (st.javaScriptEnabled === 'true' && st.allowContentAccess === 'true') n.push('D10-033: content:// readable from JS (default true; relevant once attacker content runs)');
  if (st.supportMultipleWindows === 'true') n.push('D10-029/D10-030: multiple windows on, check onCreateWindow');
  if (st.javaScriptEnabled !== 'true') n.push('JS off: bridge/file items need JS; check for a later setJavaScriptEnabled(true) (D10-018)');
  return n;
}
function dumpSettings(reason) {
  Java.scheduleOnMainThread(function () {
    Java.perform(function () {
      var count = 0, changed = 0;
      try {
        Java.choose('android.webkit.WebView', {
          onMatch: function (wv) {
            count++;
            var id, cls = '?', url = '<unavailable>';
            try { id = str(wv.hashCode()); } catch (e) { id = str(wv); }
            try { cls = wv.getClass().getName(); } catch (e) { /* keep ? */ }
            try { url = str(wv.getUrl()); } catch (e) { /* keep unavailable */ }
            var st;
            dumping = true;
            try { st = readSettings(wv); }
            catch (e) { dumping = false; unverified('getSettings() failed on ' + cls + ': ' + e, { webview: id }); return; }
            dumping = false;
            var sig = JSON.stringify(st) + '|' + url;
            if (seen[id] === sig) return;
            var isNew = !(id in seen);
            seen[id] = sig;
            changed++;
            var tags = rate(st), nts = notes(st);
            var tag = tags.length ? 'CANDIDATE' : '';
            log('[settings]' + (tag ? '[CANDIDATE]' : '') + ' ' + (isNew ? 'new' : 'changed') + ' WebView#' + id + ' ' + cls + ' url=' + url);
            log('           impl=' + st.impl);
            GETTERS.forEach(function (g) { log('           ' + g[0] + ' = ' + st[g[0]]); });
            tags.forEach(function (t) { log('           CANDIDATE ' + t.item + ': ' + t.why); });
            nts.forEach(function (t) { log('           note ' + t); });
            emit('settings', { webview: id, cls: cls, url: url, state: isNew ? 'new' : 'changed', settings: st, tag: tag,
                               items: ['D10-001'].concat(tags.map(function (t) { return t.item; })), candidates: tags, notes: nts });
          },
          onComplete: function () {}
        });
      } catch (e) {
        unverified('Java.choose(android.webkit.WebView) failed: ' + e + ' — on Android 14+ an empty or failing choose is a Frida version artefact: use frida >= 17.1.5 on host and device');
        return;
      }
      if (changed > 0 || count !== lastCount) {
        log('[dump] reason=' + reason + ' instances=' + count + ' new-or-changed=' + changed);
        emit('dump', { reason: reason, instances: count, changed: changed, items: ['D10-001'] });
      }
      lastCount = count;
    });
  });
}

// ---------- hooks on the public API class (android.webkit.WebView is concrete; apps call it directly) ------------
var getSettingsLogged = 0;
var clientHooked = {};       // class name -> true
var runtimeHooked = {};      // class name -> true (SslErrorHandler / PermissionRequest / GeolocationPermissions.Callback impls)

function factoryFor(klass) {
  try { var cl = klass.getClassLoader(); return cl === null ? Java : Java.ClassFactory.get(cl); } catch (e) { return Java; }
}
// hook methods on the RUNTIME class of an object the app receives from the framework (chromium-side subclasses)
function hookRuntimeClass(obj, methods, onCall, items) {
  var k = obj.getClass(), name = k.getName();
  if (runtimeHooked[name]) return;
  runtimeHooked[name] = true;
  var C;
  try { C = factoryFor(k).use(name); } catch (e) { unverified('cannot hook runtime class ' + name + ': ' + e); return; }
  methods.forEach(function (n) {
    var m = C[n]; if (!m) return;
    m.overloads.forEach(function (o) {
      o.implementation = function () {
        var args = Array.prototype.slice.call(arguments).map(str);
        onCall(n, args, name);
        return o.apply(this, arguments);
      };
    });
  });
  log('[hook] runtime class ' + name + ' [' + methods.join(',') + ']');
  emit('hooks', { target: name, methods: methods, items: items });
}

var CLIENT_METHODS = ['shouldOverrideUrlLoading', 'shouldInterceptRequest', 'onReceivedSslError', 'onPageStarted', 'onReceivedHttpAuthRequest'];
var CHROME_METHODS = ['onCreateWindow', 'onPermissionRequest', 'onGeolocationPermissionsShowPrompt', 'onShowFileChooser', 'onJsPrompt'];

function argUrl(method, o, args) {
  try {
    if (method === 'shouldOverrideUrlLoading' || method === 'shouldInterceptRequest') {
      var t = o.argumentTypes[1].className;
      return t === 'java.lang.String' ? str(args[1]) : str(args[1].getUrl().toString());
    }
    if (method === 'onReceivedSslError') return str(args[2].getUrl());
    if (method === 'onPageStarted') return str(args[1]);
    if (method === 'onReceivedHttpAuthRequest') return str(args[2]) + ' realm=' + str(args[3]);
    if (method === 'onGeolocationPermissionsShowPrompt') return str(args[0]);
    if (method === 'onPermissionRequest') return str(args[0].getOrigin()) + ' resources=' + str(args[0].getResources());
    if (method === 'onJsPrompt') return str(args[1]) + ' message=' + str(args[2]).slice(0, 80);
  } catch (e) { return '<unavailable: ' + e + '>'; }
  return '';
}
function describeResult(method, r) {
  if (method === 'shouldOverrideUrlLoading') return r ? 'true (app handled it)' : 'false (WebView loads it)';
  if (method === 'shouldInterceptRequest') return r === null ? 'null (default load)' : 'WebResourceResponse (app served it)';
  if (method === 'onCreateWindow') return r ? 'true (child window created)' : 'false';
  if (method === 'onJsPrompt') return r ? 'true (prompt handled natively: dispatcher-style bridge?)' : 'false';
  return str(r);
}
function hookClientMethod(C, cls, method, items) {
  var m = C[method]; if (!m) return 0;
  var n = 0;
  m.overloads.forEach(function (o) {
    o.implementation = function () {
      var self = this, args = arguments;
      return guarded('client:' + method, function () {
        var url = argUrl(method, o, args);
        var r, err = null;
        try { r = o.apply(self, args); } catch (e) { err = e; }
        var tag = '';
        if (method === 'shouldOverrideUrlLoading' && r === false && /^(javascript|file|content|intent|data)$/.test(scheme(url))) tag = 'CANDIDATE';
        if (method === 'onPermissionRequest') tag = ''; // decided by grant() below
        log('[client]' + (tag ? '[CANDIDATE]' : '') + ' ' + cls + '.' + method + '(' + url + ') -> ' + describeResult(method, r));
        emit('client-call', { cls: cls, method: method, url: url, result: describeResult(method, r), tag: tag, items: items });
        // chromium-side objects whose later call decides the item
        try {
          if (method === 'onReceivedSslError') hookRuntimeClass(args[1], ['proceed', 'cancel'], function (n2, a, rc) {
            var t = n2 === 'proceed' ? 'CANDIDATE' : '';
            log('[ssl]' + (t ? '[CANDIDATE]' : '') + ' SslErrorHandler.' + n2 + '() for ' + url);
            emit('ssl-handler', { method: n2, url: url, impl: rc, tag: t, items: ['D10-039'] });
          }, ['D10-039']);
          if (method === 'onPermissionRequest') hookRuntimeClass(args[0], ['grant', 'deny'], function (n2, a, rc) {
            var t = n2 === 'grant' ? 'CANDIDATE' : '';
            log('[perm]' + (t ? '[CANDIDATE]' : '') + ' PermissionRequest.' + n2 + '(' + a.join(',') + ') origin=' + url);
            emit('permission-request', { method: n2, args: a, origin: url, impl: rc, tag: t, items: ['D10-050'] });
          }, ['D10-050']);
          if (method === 'onGeolocationPermissionsShowPrompt') hookRuntimeClass(args[1], ['invoke'], function (n2, a, rc) {
            var allow = a[1] === 'true';
            log('[geo]' + (allow ? '[CANDIDATE]' : '') + ' GeolocationPermissions.Callback.invoke(' + a.join(',') + ')');
            emit('geolocation', { args: a, allow: allow, impl: rc, tag: allow ? 'CANDIDATE' : '', items: ['D10-051'] });
          }, ['D10-051']);
        } catch (e) { log('[note] runtime-class hook failed: ' + e); }
        if (err) throw err;
        return r;
      }, function () { return o.apply(self, args); });
    };
    n++;
  });
  return n;
}
function describeAndHookClient(client, via, methods, items) {
  if (client === null) { log('[client] ' + via + '(null)'); return; }
  var k = client.getClass(), name = k.getName(), overrides = [];
  try {
    var ms = k.getDeclaredMethods();
    for (var i = 0; i < ms.length; i++) {
      var n = ms[i].getName();
      if (methods.indexOf(n) >= 0 && overrides.indexOf(n) < 0) overrides.push(n);
    }
  } catch (e) { log('[note] getDeclaredMethods failed on ' + name + ': ' + e); }
  log('[client] ' + via + ' ' + name + ' overrides=' + (overrides.join(',') || '(none here; inherited behaviour)'));
  emit('client', { via: via, cls: name, overrides: overrides, items: items });
  if (clientHooked[name]) return;
  clientHooked[name] = true;
  var C;
  try { C = factoryFor(k).use(name); } catch (e) { unverified('cannot hook ' + name + ': ' + e); return; }
  var total = 0;
  overrides.forEach(function (n) { total += hookClientMethod(C, name, n, items); });
  if (total) { log('[hook] ' + total + ' overloads on ' + name); emit('hooks', { target: name, overloads: total, items: items }); }
}

function loadEvent(method, o, args, wv) {
  var ev = { method: method, tag: '', items: [], headers: [] };
  var a0 = str(args[0]);
  var js = 'unknown';
  dumping = true;
  try { js = str(wv.getSettings().getJavaScriptEnabled()); } catch (e) { /* keep unknown */ }
  dumping = false;
  ev.javaScriptEnabled = js;
  if (method === 'loadUrl' || method === 'postUrl') {
    ev.url = a0;
    if (args.length > 1 && method === 'loadUrl' && args[1] !== null) {
      try { // header NAMES only — never the values (docs/04: canaries, not secrets)
        var it = args[1].keySet().iterator();
        while (it.hasNext()) ev.headers.push(str(it.next()));
      } catch (e) { ev.headers = ['<unavailable>']; }
      if (ev.headers.some(function (h) { return /authorization|cookie|token|x-api|session/i.test(h); })) ev.items.push('D09-060');
    }
  } else if (method === 'loadData') {
    ev.url = 'data (' + str(args[0]).length + ' chars, mime=' + str(args[1]) + ')';
    ev.items.push('D10-023');
  } else if (method === 'loadDataWithBaseURL') {
    ev.url = 'baseUrl=' + a0 + ' historyUrl=' + str(args[4]) + ' data=' + str(args[1]).length + ' chars';
    ev.base = a0;
  } else if (method === 'evaluateJavascript') {
    ev.url = 'script(' + a0.length + ' chars): ' + a0.slice(0, 120).replace(/\s+/g, ' ');
    ev.items.push('D10-025');
  }
  var sc = scheme(method === 'loadDataWithBaseURL' ? a0 : ev.url);
  if (sc === 'javascript') { ev.tag = 'CANDIDATE'; ev.items.push('D10-025'); }
  if (sc === 'file') { ev.items.push('D10-032'); if (js === 'true') ev.tag = 'CANDIDATE'; }
  if (sc === 'content') { ev.items.push('D10-033'); }
  if (sc === 'http') { ev.items.push('D10-041'); }
  if (method === 'loadDataWithBaseURL') {
    if (a0 === 'null') ev.items.push('D10-023');
    else { ev.items.push('D10-022'); if (js === 'true' && /^(file|https?|content)$/.test(sc)) ev.tag = 'CANDIDATE'; }
  }
  if (method === 'loadUrl' || method === 'postUrl') ev.items.push('D09-059', 'D10-017');
  return ev;
}

function installWebViewHooks() {
  var WV = Java.use('android.webkit.WebView');

  // construction: the provider is loaded now -> loader discovery + setter hooks become possible
  WV.$init.overloads.forEach(function (o) {
    o.implementation = function () {
      var self = this, args = arguments;
      return guarded('init', function () {
        var r = o.apply(self, args);
        var bt = backtrace(CONFIG.stackFrames);
        var cls = self.getClass().getName();
        log('[new] ' + cls + ' <- ' + caller(bt));
        emit('webview-created', { cls: cls, stack: frames(bt), items: ['D10-001'] });
        installProviderHooks();
        dumpSettings('webview-created');
        return r;
      }, function () { return o.apply(self, args); });
    };
  });

  WV.getSettings.implementation = function () {
    var s = this.getSettings();
    if (!dumping) {
      installProviderHooks();
      if (getSettingsLogged < CONFIG.maxGetSettingsLogs) {
        getSettingsLogged++;
        var bt = backtrace(CONFIG.stackFrames);
        log('[getSettings] ' + this.getClass().getName() + ' <- ' + caller(bt));
        emit('getSettings', { cls: this.getClass().getName(), stack: frames(bt), items: ['D10-001'] });
        dumpSettings('getSettings');
      }
    }
    return s;
  };

  ['loadUrl', 'loadData', 'loadDataWithBaseURL', 'postUrl', 'evaluateJavascript'].forEach(function (m) {
    if (!WV[m]) return;
    WV[m].overloads.forEach(function (o) {
      o.implementation = function () {
        var ev = loadEvent(m, o, arguments, this);
        var bt = backtrace(CONFIG.stackFrames);
        ev.stack = frames(bt);
        ev.cls = this.getClass().getName();
        log('[load]' + (ev.tag ? '[CANDIDATE]' : '') + ' ' + m + ' ' + ev.url + (ev.headers.length ? ' headers=' + ev.headers.join(',') : '')
            + ' js=' + ev.javaScriptEnabled + ' <- ' + caller(bt));
        emit('load', ev);
        return o.apply(this, arguments);
      };
    });
  });

  WV.setWebViewClient.implementation = function (c) {
    var r = this.setWebViewClient(c);
    describeAndHookClient(c, 'setWebViewClient', CLIENT_METHODS, ['D10-002', 'D10-020', 'D10-039']);
    return r;
  };
  WV.setWebChromeClient.implementation = function (c) {
    var r = this.setWebChromeClient(c);
    describeAndHookClient(c, 'setWebChromeClient', CHROME_METHODS, ['D10-030', 'D10-037', 'D10-050', 'D10-051', 'D10-058']);
    return r;
  };
  WV.setWebContentsDebuggingEnabled.implementation = function (b) {
    var bt = backtrace(CONFIG.stackFrames);
    log('[debug]' + (b ? '[CANDIDATE]' : '') + ' setWebContentsDebuggingEnabled(' + b + ') <- ' + caller(bt));
    emit('debugging', { enabled: !!b, tag: b ? 'CANDIDATE' : '', items: ['D10-049'], stack: frames(bt) });
    return this.setWebContentsDebuggingEnabled(b);
  };
  log('[hook] android.webkit.WebView: $init, getSettings, loadUrl/loadData/loadDataWithBaseURL/postUrl/evaluateJavascript, setWebViewClient, setWebChromeClient, setWebContentsDebuggingEnabled');
}

// base-class hooks fire only when the app does NOT override (then the default: false / null)
function installBaseClientHooks() {
  var n = 0;
  try {
    var B = Java.use('android.webkit.WebViewClient');
    ['shouldOverrideUrlLoading', 'shouldInterceptRequest'].forEach(function (m) { n += hookClientMethod(B, 'android.webkit.WebViewClient', m, ['D10-020']); });
  } catch (e) { unverified('android.webkit.WebViewClient base hooks failed: ' + e); }
  if (n) log('[hook] ' + n + ' overloads on android.webkit.WebViewClient (base: reached only when not overridden)');
}

// ---------- timer + rpc ----------------------------------------------------------------------------------------
var timer = null;
function startTimer() {
  if (timer) { clearInterval(timer); timer = null; }
  if (CONFIG.rescanMs > 0) {
    timer = setInterval(function () { Java.perform(function () { installProviderHooks(); dumpSettings('timer'); }); }, CONFIG.rescanMs);
  }
}
rpc.exports = {
  dump: function () { Java.perform(function () { installProviderHooks(); dumpSettings('rpc'); }); return 'dump scheduled on the UI thread'; },
  rescan: function () { var ok = false; Java.perform(function () { ok = installProviderHooks(); dumpSettings('rpc'); }); return ok ? 'provider loader ready' : 'provider loader not found yet (no WebView constructed so far)'; },
  setrescan: function (ms) { CONFIG.rescanMs = Number(ms) || 0; startTimer(); return 'rescanMs=' + CONFIG.rescanMs; },
  status: function () {
    return { provider: provider ? provider.settingsClass : null, providerHooked: providerHooked, webviews: Object.keys(seen).length,
             clients: Object.keys(clientHooked), runtimeClasses: Object.keys(runtimeHooked) };
  }
};

// ---------- main -----------------------------------------------------------------------------------------------
Java.perform(function () {
  try { installWebViewHooks(); } catch (e) { unverified('android.webkit.WebView hooks failed: ' + e); }
  installBaseClientHooks();
  installProviderHooks();      // succeeds immediately in attach mode when a WebView already exists
  dumpSettings('start');       // empty at spawn by construction; the timer and the constructor hook catch up
  startTimer();
  log('[ready] rescan every ' + CONFIG.rescanMs + ' ms; rpc.exports: dump(), rescan(), setrescan(ms), status()');
  emit('ready', { rescanMs: CONFIG.rescanMs, frida: Frida.version, items: ['D10-001'] });
});
