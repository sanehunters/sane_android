/* D12 — what cipher, key and IV are ACTUALLY used at runtime. */
Java.perform(function () {
  var C = Java.use('javax.crypto.Cipher');
  C.getInstance.overload('java.lang.String').implementation = function (t) {
    console.log('\n[Cipher.getInstance] ' + t);
    if (/ECB|^AES$|^DES|RC4|MD5/i.test(t)) console.log('   !! broken or default-ECB transformation');
    return this.getInstance(t);
  };
  var b64 = function (b) { try { return Java.use('android.util.Base64').encodeToString(b, 0); } catch (e) { return '?'; } };
  var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
  SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
    console.log('[SecretKeySpec] alg=' + a + ' len=' + k.length + ' key(b64)=' + b64(k));
    console.log('   -> a key visible here is a key that is IN THE APK or derivable from it');
    return this.$init(k, a);
  };
  var IV = Java.use('javax.crypto.spec.IvParameterSpec');
  IV.$init.overload('[B').implementation = function (iv) {
    console.log('[IvParameterSpec] len=' + iv.length + ' iv(b64)=' + b64(iv));
    console.log('   -> record these across runs: a CONSTANT IV is the finding, not the algorithm');
    return this.$init(iv);
  };
});
