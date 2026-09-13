/* D09 — trace a URI from the entry point to the sink it reaches. */
Java.perform(function () {
  var A = Java.use('android.app.Activity');
  ['getIntent'].forEach(function (m) {
    A[m].implementation = function () {
      var i = this[m]();
      try {
        var d = i.getData();
        if (d) console.log('\n[getIntent] ' + this.getClass().getName() + '  data=' + d.toString());
      } catch (e) {}
      return i;
    };
  });
  var U = Java.use('android.net.Uri');
  ['getQueryParameter', 'getHost', 'getPath', 'getLastPathSegment'].forEach(function (m) {
    if (!U[m]) return;
    U[m].overloads.forEach(function (o) {
      o.implementation = function () {
        var r = o.apply(this, arguments);
        console.log('  Uri.' + m + '(' + (arguments[0] || '') + ') -> ' + r);
        return r;
      };
    });
  });
  // The sinks that turn a deep link into a finding.
  var Ctx = Java.use('android.content.ContextWrapper');
  Ctx.startActivity.overload('android.content.Intent').implementation = function (i) {
    console.log('  [SINK startActivity] comp=' + i.getComponent() + ' data=' + i.getData()
                + ' flags=0x' + i.getFlags().toString(16));
    return this.startActivity(i);
  };
});
