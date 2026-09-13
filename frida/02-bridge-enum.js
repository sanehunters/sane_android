/* D10 — enumerate every JS bridge and RATE IT BY WHAT EACH METHOD RETURNS.
 * A bridge that returns a token is a different finding from one that returns a boolean. */
Java.perform(function () {
  var WV = Java.use('android.webkit.WebView');
  WV.addJavascriptInterface.implementation = function (obj, name) {
    console.log('\n=== addJavascriptInterface("' + name + '") ===');
    try {
      var C = Java.use('java.lang.Class');
      var methods = C.getDeclaredMethods.call(obj.getClass());
      methods.forEach(function (m) {
        var sig = m.toString();
        var exposed = false;
        try {
          m.getAnnotations().forEach(function (a) {
            if (a.toString().indexOf('JavascriptInterface') >= 0) exposed = true;
          });
        } catch (e) {}
        if (exposed || sig.indexOf('public') >= 0)
          console.log('  ' + (exposed ? '[@JS] ' : '      ') + sig);
      });
      console.log('  -> call from JS as: ' + name + '.<method>(...)');
      console.log('  -> minSdk < 17? every public method is reachable by reflection => RCE');
      console.log('  -> can a CROSS-ORIGIN IFRAME reach this? the allow-list usually gates only the main frame');
    } catch (e) { console.log('  enum failed: ' + e); }
    return this.addJavascriptInterface(obj, name);
  };
});
