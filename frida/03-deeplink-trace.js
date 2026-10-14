/* 03-deeplink-trace.js — D09: trace a URI from the entry point to the sink it reaches.
 *
 * Run      spawn:  frida -D $ANDROID_SERIAL -f <pkg> -l frida/03-deeplink-trace.js -t 120 -q | tee $E/logs/frida-03-$(date +%s).log
 *          then fire the link: adb shell am start -W -a android.intent.action.VIEW -d '<uri>' <pkg>
 *          attach works too (the handler runs on every delivery), but a link delivered BEFORE attach is not seen.
 *
 * Why these classes (README rule 1: a hook on an abstract class records nothing)
 *  - android.net.Uri.getHost/getPath/getLastPathSegment/getScheme/getAuthority are ABSTRACT. The concrete classes
 *    are the nested android.net.Uri$HierarchicalUri (Uri.parse of anything with '://'), Uri$StringUri and
 *    Uri$OpaqueUri; each is hooked separately. getQueryParameter/getQueryParameterNames/getBooleanQueryParameter
 *    are concrete on android.net.Uri itself and stay there.
 *  - startActivity from an Activity never passes through ContextWrapper.startActivity (Activity overrides it and
 *    calls Instrumentation.execStartActivity). The choke point is android.app.Instrumentation.execStartActivity,
 *    hooked on every overload; Activity.startActivity / startActivityForResult and ContextImpl.startActivity are
 *    hooked as well for provenance, plus the other D08 sinks: startService, sendBroadcast, PendingIntent.send.
 *  - Every hook is installed in its own try/catch and reported as [03][UNVERIFIED] on failure, so one missing
 *    class (vendor builds, different nested-class names) can never abort the sink hooks.
 *
 * Zero result means
 *  - "[03][UNVERIFIED] hook X failed" = that source/sink was NOT observed; do not read its silence.
 *  - Uri lines but no [SINK] line = the link was parsed but nothing was launched while attached: a negative for
 *    D09->D08 only after the handler's code path was read in $DEC (the sink may be a WebView.loadUrl — frida/01).
 *  - no lines at all = the link never reached this process (wrong package, not BROWSABLE, App Link verified
 *    elsewhere): check `adb shell am start -W` output and dumpsys package d. */
'use strict';
var P = '[03]';
function unverified(m) { console.log(P + '[UNVERIFIED] ' + m); }
function hook(className, method, cb) {     // all overloads, own try/catch, never throws
  var C; try { C = Java.use(className); } catch (e) { unverified('hook ' + className + '.' + method + ' failed: ' + e); return 0; }
  var n = 0;
  try {
    if (!C[method]) { unverified(className + '.' + method + ' not present on this build'); return 0; }
    C[method].overloads.forEach(function (o) {
      try {
        o.implementation = function () { return cb.call(this, o, arguments); };
        n++;
      } catch (e) { unverified('hook ' + className + '.' + method + '(' + o.argumentTypes.map(function (t) { return t.className; }).join(',') + ') failed: ' + e); }
    });
  } catch (e) { unverified('hook ' + className + '.' + method + ' failed: ' + e); }
  return n;
}
function intentArg(o, args) {               // the android.content.Intent argument of any overload, or null
  for (var i = 0; i < o.argumentTypes.length; i++) if (o.argumentTypes[i].className === 'android.content.Intent' && args[i]) return args[i];
  return null;
}
function caller() {
  try {
    var st = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()).split('\n');
    for (var i = 1; i < st.length; i++) if (st[i].indexOf('android.') < 0 && st[i].indexOf('java.') < 0 && st[i].indexOf('com.android.') < 0) return st[i].trim();
  } catch (e) {}
  return '?';
}
function sink(kind, o, args, extra) {
  var i = intentArg(o, args);
  var line = '  [SINK ' + kind + '] ' + (i ? 'comp=' + i.getComponent() + ' action=' + i.getAction() + ' data=' + i.getData() + ' flags=0x' + i.getFlags().toString(16)
             + ' extras=' + (i.getExtras() ? i.getExtras().keySet() : '[]') : '') + (extra || '') + ' caller=' + caller();
  console.log(line);
  try { send({ script: '03-deeplink-trace', ev: 'sink', kind: kind, comp: i ? String(i.getComponent()) : null, data: i ? String(i.getData()) : null, tag: 'CANDIDATE', items: ['D09-001', 'D08-001'] }); } catch (e) {}
}
Java.perform(function () {
  // Entry: which Activity received a URI
  hook('android.app.Activity', 'getIntent', function (o, args) {
    var i = o.apply(this, args);
    try { var d = i.getData(); if (d) console.log('\n' + P + ' [getIntent] ' + this.getClass().getName() + '  data=' + d.toString()); } catch (e) {}
    return i;
  });
  // Parsing: the CONCRETE Uri classes (abstract getters on android.net.Uri record nothing)
  var concrete = ['android.net.Uri$HierarchicalUri', 'android.net.Uri$StringUri', 'android.net.Uri$OpaqueUri'];
  var getters = ['getScheme', 'getAuthority', 'getHost', 'getPath', 'getLastPathSegment'];
  concrete.forEach(function (cn) {
    getters.forEach(function (m) {
      hook(cn, m, function (o, args) {
        var r = o.apply(this, args);
        console.log('  Uri.' + m + '() -> ' + r + '   [' + cn.split('$')[1] + ']');
        return r;
      });
    });
  });
  ['getQueryParameter', 'getQueryParameterNames', 'getBooleanQueryParameter'].forEach(function (m) {
    hook('android.net.Uri', m, function (o, args) {
      var r = o.apply(this, args);
      console.log('  Uri.' + m + '(' + (args[0] !== undefined ? args[0] : '') + ') -> ' + r);
      return r;
    });
  });
  // Sinks: the choke point first, then provenance and the other D08 shapes
  hook('android.app.Instrumentation', 'execStartActivity', function (o, args) { sink('execStartActivity', o, args); return o.apply(this, args); });
  ['startActivity', 'startActivityForResult'].forEach(function (m) {
    hook('android.app.Activity', m, function (o, args) { sink('Activity.' + m, o, args); return o.apply(this, args); });
  });
  hook('android.app.ContextImpl', 'startActivity', function (o, args) { sink('ContextImpl.startActivity', o, args); return o.apply(this, args); });
  ['startService', 'startForegroundService', 'sendBroadcast', 'sendOrderedBroadcast', 'bindService'].forEach(function (m) {
    hook('android.app.ContextImpl', m, function (o, args) { sink('ContextImpl.' + m, o, args); return o.apply(this, args); });
  });
  hook('android.app.PendingIntent', 'send', function (o, args) {
    sink('PendingIntent.send', o, args, ' pi=' + this.toString());
    return o.apply(this, args);
  });
  console.log(P + ' ready: fire the link now (adb shell am start -W -a android.intent.action.VIEW -d "<uri>" <pkg>)');
});
