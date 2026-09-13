/* D11 — every file the app touches after login. Run, then log in, then read the list. */
Java.perform(function () {
  var F = Java.use('java.io.File');
  var seen = {};
  ['java.io.FileOutputStream', 'java.io.FileInputStream'].forEach(function (cn) {
    var S = Java.use(cn);
    S.$init.overload('java.io.File').implementation = function (f) {
      var p = f.getAbsolutePath();
      if (!seen[p]) { seen[p] = 1; console.log('[' + (cn.indexOf('Output') > 0 ? 'W' : 'R') + '] ' + p); }
      return this.$init(f);
    };
  });
  var SP = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  ['putString'].forEach(function (m) {
    SP[m].implementation = function (k, v) {
      var s = String(v);
      if (/eyJ|Bearer |token|secret|password/i.test(s) || /eyJ|token/i.test(String(k)))
        console.log('[prefs] ' + k + ' = ' + (s.length > 120 ? s.substring(0,120)+'...' : s));
      return this[m](k, v);
    };
  });
});
