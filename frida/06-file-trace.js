/* 06-file-trace.js — D11: every file the app opens, every SharedPreferences write, and the LIVE prefs state.
 *
 * Run      spawn:  frida -D $ANDROID_SERIAL -f <pkg> -l frida/06-file-trace.js -t 180 -q | tee $E/logs/frida-06-$(date +%s).log
 *          then log in and exercise the app. SPAWN MODE IS REQUIRED for login-time writes: the open/write hooks are
 *          call-time and a token written before attach is never shown by them.
 *          attach: timeout 120 frida -D $ANDROID_SERIAL -n <pkg> -l frida/06-file-trace.js  -> REPL: rpc.exports.dump()
 *          dump() reads the state that is true NOW off the live SharedPreferencesImpl objects (README rule 2).
 *
 * What is hooked — the TERMINAL constructors, so every overload funnels through them
 *   java.io.FileOutputStream(File, boolean)   <- (String), (String,boolean), (File) and Context.openFileOutput() all chain here
 *   java.io.FileInputStream(File)             <- (String) chains here
 *   java.io.RandomAccessFile(File, String)    <- (String, String) chains here
 *   android.database.sqlite.SQLiteDatabase.openDatabase (all overloads)   DB files
 *   SharedPreferencesImpl$EditorImpl.putString/putStringSet/putInt/putLong/putFloat/putBoolean + apply()/commit()
 *
 * Zero result means
 *  - "[06][UNVERIFIED] ..." = a hook or the live dump could not run; not tested.
 *  - no [W] lines in attach mode = expected (writes happened before attach); use dump() and the static read of
 *    /data/data/<pkg> (D11) — the setter hook is provenance, the dump is the truth.
 *  - no [prefs] match = no value matched the secret regex while attached; dump() applies the same regex to every
 *    live value. A clean D11 needs the on-disk read as well. */
'use strict';
var P = '[06]';
var SECRET = /eyJ|Bearer |token|secret|password|passwd|apikey|api_key|session|auth/i;
var seen = {};
function unverified(m) { console.log(P + '[UNVERIFIED] ' + m); }
function hook(className, method, cb) {
  var C; try { C = Java.use(className); } catch (e) { unverified('hook ' + className + '.' + method + ' failed: ' + e); return; }
  try {
    C[method].overloads.forEach(function (o) {
      try { o.implementation = function () { return cb.call(this, o, arguments); }; }
      catch (e) { unverified('hook ' + className + '.' + method + ' overload failed: ' + e); }
    });
  } catch (e) { unverified('hook ' + className + '.' + method + ' failed: ' + e); }
}
function trunc(s) { s = String(s); return s.length > 120 ? s.substring(0, 120) + '...' : s; }
function note(kind, p) {
  if (seen[kind + p]) return; seen[kind + p] = 1;
  var ext = /\/sdcard|\/storage\/|\/mnt\//.test(p) ? '   !! EXTERNAL storage (world-readable before API 29, scoped after)' : '';
  console.log('[' + kind + '] ' + p + ext);
  try { send({ script: '06-file-trace', ev: 'file', kind: kind, path: p, tag: ext ? 'CANDIDATE' : '', items: ['D11-001'] }); } catch (e) {}
}
Java.perform(function () {
  hook('java.io.FileOutputStream', '$init', function (o, args) {
    if (o.argumentTypes.length === 2 && o.argumentTypes[0].className === 'java.io.File') {       // terminal (File, boolean)
      try { if (args[0]) note(args[1] ? 'W+' : 'W', args[0].getAbsolutePath()); } catch (e) {}
    }
    return o.apply(this, args);
  });
  hook('java.io.FileInputStream', '$init', function (o, args) {
    if (o.argumentTypes.length === 1 && o.argumentTypes[0].className === 'java.io.File') {       // terminal (File)
      try { if (args[0]) note('R', args[0].getAbsolutePath()); } catch (e) {}
    }
    return o.apply(this, args);
  });
  hook('java.io.RandomAccessFile', '$init', function (o, args) {
    if (o.argumentTypes[0].className === 'java.io.File') { try { note('RAF:' + args[1], args[0].getAbsolutePath()); } catch (e) {} }
    return o.apply(this, args);
  });
  hook('android.database.sqlite.SQLiteDatabase', 'openDatabase', function (o, args) {
    try { note('DB', o.argumentTypes[0].className === 'java.io.File' ? args[0].getAbsolutePath() : String(args[0])); } catch (e) {}
    return o.apply(this, args);
  });
  var EDITOR = 'android.app.SharedPreferencesImpl$EditorImpl';
  ['putString', 'putStringSet', 'putInt', 'putLong', 'putFloat', 'putBoolean'].forEach(function (m) {
    hook(EDITOR, m, function (o, args) {
      var k = String(args[0]), v = String(args[1]);
      if (SECRET.test(v) || SECRET.test(k)) {
        console.log('[prefs.' + m + '] ' + k + ' = ' + trunc(v) + '   (CANDIDATE D11: secret-shaped value in SharedPreferences)');
        try { send({ script: '06-file-trace', ev: 'prefs', key: k, tag: 'CANDIDATE', items: ['D11-003'] }); } catch (e) {}
      }
      return o.apply(this, args);
    });
  });
  ['apply', 'commit'].forEach(function (m) {
    hook(EDITOR, m, function (o, args) {
      try {
        var f = this.getClass().getDeclaredField('this$0'); f.setAccessible(true);
        var impl = f.get(this), mf = impl.getClass().getDeclaredField('mFile'); mf.setAccessible(true);
        note('W(prefs.' + m + ')', String(Java.cast(mf.get(impl), Java.use('java.io.File')).getAbsolutePath()));
      } catch (e) {}
      return o.apply(this, args);
    });
  });
  // Live read: what is in every loaded SharedPreferences NOW (attach mode's truth)
  function dump() {
    var n = 0;
    try {
      Java.choose('android.app.SharedPreferencesImpl', {
        onMatch: function (sp) {
          n++;
          try {
            var c = sp.getClass();
            var mf = c.getDeclaredField('mFile'); mf.setAccessible(true);
            var mm = c.getDeclaredField('mMap'); mm.setAccessible(true);
            var file = String(Java.cast(mf.get(sp), Java.use('java.io.File')).getAbsolutePath());
            var map = Java.cast(mm.get(sp), Java.use('java.util.Map'));
            console.log('\n' + P + ' prefs ' + file + ' (' + map.size() + ' keys)');
            var it = map.entrySet().iterator();
            while (it.hasNext()) {
              var e = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
              var k = String(e.getKey()), v = String(e.getValue());
              var hit = SECRET.test(k) || SECRET.test(v);
              console.log('  ' + (hit ? '!! ' : '   ') + k + ' = ' + trunc(v) + (hit ? '   (CANDIDATE D11)' : ''));
            }
          } catch (e2) { unverified('reading SharedPreferencesImpl fields failed: ' + e2 + ' (hidden-field names moved on this build)'); }
        },
        onComplete: function () {}
      });
    } catch (e) { unverified('Java.choose(android.app.SharedPreferencesImpl) failed: ' + e); }
    console.log(P + ' live SharedPreferences objects: ' + n + (n === 0 ? ' (none loaded yet, or choose unsupported: Android 14+ needs frida >= 17.1.5)' : ''));
    return n;
  }
  rpc.exports = { dump: dump };
  console.log(P + ' ready: terminal constructors + prefs editor hooked (call-time); rpc.exports.dump() reads live prefs');
});
