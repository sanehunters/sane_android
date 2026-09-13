/* D10 — read WebView settings off LIVE objects, not from setter hooks.
 * Hooking android.webkit.WebSettings records NOTHING: the concrete class differs. */
Java.perform(function () {
  var targets = ['org.chromium.android_webview.AwSettings',
                 'com.android.webview.chromium.ContentSettingsAdapter',
                 'android.webkit.WebSettings'];
  targets.forEach(function (cn) {
    try {
      Java.choose(cn, {
        onMatch: function (s) {
          console.log('\n=== ' + cn + ' @ ' + s.$h + ' ===');
          var q = function (n, f) { try { console.log('  ' + n + ' = ' + f()); } catch (e) {} };
          q('javaScriptEnabled',              function () { return s.getJavaScriptEnabled(); });
          q('allowFileAccess',                function () { return s.getAllowFileAccess(); });
          q('allowFileAccessFromFileURLs',    function () { return s.getAllowFileAccessFromFileURLs(); });
          q('allowUniversalAccessFromFileURLs', function () { return s.getAllowUniversalAccessFromFileURLs(); });
          q('allowContentAccess',             function () { return s.getAllowContentAccess(); });
          q('domStorageEnabled',              function () { return s.getDomStorageEnabled(); });
          q('mixedContentMode',               function () { return s.getMixedContentMode(); });
          q('safeBrowsingEnabled',            function () { return s.getSafeBrowsingEnabled(); });
          q('userAgentString',                function () { return s.getUserAgentString(); });
          console.log('  -> allowUniversalAccessFromFileURLs=true + a file:// load = universal XSS');
        },
        onComplete: function () {}
      });
    } catch (e) { console.log('[skip] ' + cn); }
  });

  // Every URL actually loaded, with a stack so you can find the caller.
  ['android.webkit.WebView'].forEach(function (cn) {
    var W = Java.use(cn);
    ['loadUrl', 'loadDataWithBaseURL', 'postUrl'].forEach(function (m) {
      if (!W[m]) return;
      W[m].overloads.forEach(function (o) {
        o.implementation = function () {
          console.log('\n[' + m + '] ' + arguments[0]);
          console.log(Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new()).split('\n').slice(1, 8).join('\n'));
          return o.apply(this, arguments);
        };
      });
    });
  });
});
