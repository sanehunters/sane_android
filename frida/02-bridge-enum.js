/* 02-bridge-enum.js — D10: every JS bridge, RATED BY WHAT EACH METHOD RETURNS.
 * A bridge that returns a token (String/Bundle/JSONObject/byte[]) is a different finding from one that returns
 * a boolean; a void method with parameters is a sink (what can a page make the app DO?).
 *
 * Run      spawn:  frida -D $ANDROID_SERIAL -f <pkg> -l frida/02-bridge-enum.js -t 120 -q | tee $E/logs/frida-02-$(date +%s).log
 *          attach: timeout 120 frida -D $ANDROID_SERIAL -n <pkg> -l frida/02-bridge-enum.js   -> REPL: rpc.exports.dump()
 *
 * Mode     The addJavascriptInterface hook is CALL-TIME: it only sees bridges registered while attached, so in
 *          attach mode (RASP-protected apps, D21) it prints nothing for a WebView built before you attached.
 *          rpc.exports.dump() is the live read (README rule 2): it walks every live android.webkit.WebView and,
 *          through the WebView provider's class loader, the chromium JavascriptInjectorImpl registry.
 *
 * Zero result means
 *  - "[02][UNVERIFIED] ..." = a hook or the live walk could not run. Not tested; fix the harness (D26) and re-run.
 *  - 0 lines in attach mode = UNVERIFIED (the bridge was registered before attach): re-run in spawn mode or dump().
 *  - 0 bridges after a FULL UI walk in spawn mode + dump() = no live bridge at that moment. A negative for D10
 *    only together with a static zero for addJavascriptInterface / @JavascriptInterface in $DEC. */
'use strict';
var P = '[02]';
function unverified(m) { console.log(P + '[UNVERIFIED] ' + m); }
function use(name) {                       // Java.use with a class-loader fallback (dynamic features, delegate loaders)
  try { return Java.use(name); } catch (e0) {
    var loaders = []; try { loaders = Java.enumerateClassLoadersSync(); } catch (e1) {}
    for (var i = 0; i < loaders.length; i++) {
      try { loaders[i].loadClass(name); return Java.ClassFactory.get(loaders[i]).use(name); } catch (e2) {}
    }
    throw e0;
  }
}
var seen = {};
function rate(cls, name) {                 // one line per method; CANDIDATE tag by return type
  var key = cls.getName() + '@' + name; if (seen[key]) return; seen[key] = 1;
  console.log('\n' + P + ' bridge "' + name + '" -> ' + cls.getName());
  var any = false;
  try {
    var methods = cls.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
      var m = methods[i], exposed = false;
      try { var ann = m.getAnnotations(); for (var k = 0; k < ann.length; k++) if (String(ann[k]).indexOf('JavascriptInterface') >= 0) exposed = true; } catch (e) {}
      var ret = m.getReturnType().getName(), params = m.getParameterTypes().length;
      var tag = '';
      if (/String|Bundle|JSONObject|JSONArray|\[B|Map|List|Object$/.test(ret) && ret !== 'void') tag = ' CANDIDATE(returns ' + ret + ': D10-003+ data return)';
      else if (ret === 'void' && params > 0) tag = ' CANDIDATE(sink: ' + params + ' params, D10-004+)';
      if (exposed || (Modifier && Modifier.isPublic(m.getModifiers()))) {
        any = true;
        console.log('  ' + (exposed ? '[@JS] ' : '[pub] ') + ret + ' ' + m.getName() + '(' + params + ')' + tag);
        try { send({ script: '02-bridge-enum', ev: 'method', bridge: name, cls: cls.getName(), method: m.getName(), ret: ret, params: params, exposed: exposed, tag: tag ? 'CANDIDATE' : '' }); } catch (e) {}
      }
    }
  } catch (e) { unverified('method walk failed for ' + key + ': ' + e); }
  if (!any) console.log('  (no public methods)');
  console.log('  -> call from JS as: ' + name + '.<method>(...)');
  console.log('  -> minSdk < 17? every public method is reachable by reflection => RCE');
  console.log('  -> can a CROSS-ORIGIN IFRAME reach this? the allow-list usually gates only the main frame');
}
var Modifier = null;
Java.perform(function () {
  try { Modifier = Java.use('java.lang.reflect.Modifier'); } catch (e) { unverified('Modifier: ' + e); }
  // 1. call-time: every addJavascriptInterface overload (spawn mode)
  try {
    var WV = Java.use('android.webkit.WebView');
    WV.addJavascriptInterface.overloads.forEach(function (o) {
      o.implementation = function (obj, name) {
        try { rate(obj.getClass(), name); } catch (e) { unverified('rate failed: ' + e); }
        return o.apply(this, arguments);
      };
    });
  } catch (e) { unverified('hook android.webkit.WebView.addJavascriptInterface failed: ' + e); }
  // 2. live read: walk the chromium injector registry through the provider's loader (attach mode)
  function dump() {
    var n = 0;
    try {
      Java.choose('android.webkit.WebView', { onMatch: function () { n++; }, onComplete: function () {} });
    } catch (e) { unverified('Java.choose(android.webkit.WebView) failed: ' + e + ' (Android 14+: use frida >= 17.1.5 on both sides)'); }
    console.log(P + ' live WebView instances: ' + n);
    var found = 0;
    try {
      var loaders = Java.enumerateClassLoadersSync();
      for (var i = 0; i < loaders.length; i++) {
        var F;
        try { loaders[i].loadClass('org.chromium.content.browser.JavascriptInjectorImpl'); F = Java.ClassFactory.get(loaders[i]); } catch (e) { continue; }
        F.choose('org.chromium.content.browser.JavascriptInjectorImpl', {
          onMatch: function (inj) {
            try {
              var f = inj.getClass().getDeclaredField('mInjectedObjects'); f.setAccessible(true);
              var map = Java.cast(f.get(inj), Java.use('java.util.Map'));
              var it = map.entrySet().iterator();
              while (it.hasNext()) {
                var e = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
                var name = String(e.getKey()), pair = e.getValue();
                var obj = null; try { obj = Java.cast(pair, Java.use('android.util.Pair')).first.value; } catch (x) { obj = pair; }
                found++; rate(Java.cast(obj, Java.use('java.lang.Object')).getClass(), name);
              }
            } catch (e2) { unverified('injector field walk failed: ' + e2 + ' (chromium internals moved; fall back to spawn mode)'); }
          }, onComplete: function () {} });
        break;
      }
      if (!F) unverified('no loader holds org.chromium.content.browser.JavascriptInjectorImpl: either no WebView was created yet or the provider is not chromium — spawn mode is the fallback');
    } catch (e) { unverified('class-loader walk failed: ' + e); }
    console.log(P + ' live bridges found: ' + found);
    return found;
  }
  rpc.exports = { dump: dump };
  console.log(P + ' ready: addJavascriptInterface hooked (call-time); rpc.exports.dump() reads live bridges');
});
