/* 04-crypto-trace.js — D12: what cipher, key and IV are ACTUALLY used at runtime, tied together by Cipher.init.
 *
 * Run      spawn:  frida -D $ANDROID_SERIAL -f <pkg> -l frida/04-crypto-trace.js -t 120 -q | tee $E/logs/frida-04-$(date +%s).log
 *          Spawn mode is required for login-time crypto; in attach mode a key built before attach is never seen.
 *
 * What is hooked (EVERY overload of each; one overload hooked = the provider-qualified or sliced-array call is missed)
 *   Cipher.getInstance(String | String,String | String,Provider)      the transformation, with the provider
 *   SecretKeySpec(<init>)  ([B,String) and ([B,int,int,String)           key length + a key FINGERPRINT (never the key)
 *   IvParameterSpec(<init>) ([B) and ([B,int,int)                       the IV in full (an IV is not a secret) + repeat count
 *   GCMParameterSpec(<init>) (int,[B) and (int,[B,int,int)              tag bits + nonce + repeat count: a REUSED GCM nonce
 *                                                                       is the catastrophic case
 *   Cipher.init(int,Key[,AlgorithmParameterSpec|AlgorithmParameters|SecureRandom])  mode, key algorithm + fingerprint,
 *                                                                       params class, and the transformation of THIS cipher
 *
 * Secrets (docs/04: canaries, not secrets; the pre-commit hook blocks live-looking credentials)
 *   Keys are printed as len + sha256[0:8]. rpc.exports.reveal(true) prints full key bytes (base64) for a DELIBERATE
 *   capture into $E/sensitive/ (0600) when the key is demonstrably in the APK; never tee that run into logs/.
 *
 * Zero result means
 *  - "[04][UNVERIFIED] hook X failed" = that API was not observed.
 *  - no lines after the login flow = the app does not use javax.crypto on that path (native crypto, Tink via its own
 *    classes, or Keystore-only operations): a negative only with a static read of $DEC for Cipher/BoringSSL/Tink. */
'use strict';
var P = '[04]';
var REVEAL = false;
var ivSeen = {}, cipherOf = {};
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
function bytes(b, off, len) {              // JS array of the byte[] slice
  var out = []; var n = len === undefined ? b.length : len; var o = off || 0;
  for (var i = 0; i < n; i++) out.push(b[o + i] & 0xff);
  return out;
}
function b64(arr) { try { return Java.use('android.util.Base64').encodeToString(Java.array('byte', arr.map(function (x) { return x > 127 ? x - 256 : x; })), 2); } catch (e) { return '?'; } }
function fp(arr) {                          // sha256(key)[0:8] hex — a fingerprint, not the key
  try {
    var md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
    var d = md.digest(Java.array('byte', arr.map(function (x) { return x > 127 ? x - 256 : x; })));
    var s = ''; for (var i = 0; i < 4; i++) s += ('0' + (d[i] & 0xff).toString(16)).slice(-2);
    return s;
  } catch (e) { return '?'; }
}
function keyLine(alg, arr) { return 'alg=' + alg + ' len=' + arr.length + ' sha256[0:8]=' + fp(arr) + (REVEAL ? ' key(b64)=' + b64(arr) : ''); }
function ivLine(kind, arr, extra) {
  var k = b64(arr); ivSeen[k] = (ivSeen[k] || 0) + 1;
  var line = '[' + kind + '] len=' + arr.length + (extra || '') + ' iv(b64)=' + k + ' seen=' + ivSeen[k] + 'x';
  if (ivSeen[k] > 1) line += '   !! REPEATED IV/nonce (CANDIDATE D12: constant IV; with GCM this is catastrophic)';
  console.log(line);
  try { send({ script: '04-crypto-trace', ev: kind, len: arr.length, iv: k, seen: ivSeen[k], tag: ivSeen[k] > 1 ? 'CANDIDATE' : '', items: ['D12-004'] }); } catch (e) {}
}
Java.perform(function () {
  hook('javax.crypto.Cipher', 'getInstance', function (o, args) {
    var t = String(args[0]), prov = args.length > 1 ? ' provider=' + String(args[1]) : '';
    console.log('\n[Cipher.getInstance] ' + t + prov);
    if (/ECB|^AES$|^DES|RC4|MD5/i.test(t)) console.log('   !! broken or default-ECB transformation (CANDIDATE D12)');
    var c = o.apply(this, args);
    try { cipherOf[c.hashCode()] = t; } catch (e) {}
    return c;
  });
  hook('javax.crypto.spec.SecretKeySpec', '$init', function (o, args) {
    var arr = args.length === 4 ? bytes(args[0], args[1], args[2]) : bytes(args[0]);
    console.log('[SecretKeySpec] ' + keyLine(String(args[args.length - 1]), arr) + (args.length === 4 ? ' (sliced off=' + args[1] + ')' : ''));
    console.log('   -> a key visible here is a key that is IN THE APK or derivable from it; find it in $DEC before calling it hardcoded');
    return o.apply(this, args);
  });
  hook('javax.crypto.spec.IvParameterSpec', '$init', function (o, args) {
    ivLine('IvParameterSpec', args.length === 3 ? bytes(args[0], args[1], args[2]) : bytes(args[0]));
    return o.apply(this, args);
  });
  hook('javax.crypto.spec.GCMParameterSpec', '$init', function (o, args) {
    ivLine('GCMParameterSpec', args.length === 4 ? bytes(args[1], args[2], args[3]) : bytes(args[1]), ' tagBits=' + args[0]);
    return o.apply(this, args);
  });
  hook('javax.crypto.Cipher', 'init', function (o, args) {
    var mode = ['?', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP'][args[0]] || args[0];
    var key = args[1], kalg = '?', kfp = '';
    try { kalg = String(key.getAlgorithm()); var enc = key.getEncoded(); if (enc) kfp = ' keyLen=' + enc.length + ' sha256[0:8]=' + fp(bytes(enc)); else kfp = ' key=non-extractable(Keystore)'; } catch (e) {}
    var params = args.length > 2 && args[2] ? String(args[2].$className || args[2].getClass().getName()) : 'none';
    var t = '?'; try { t = cipherOf[this.hashCode()] || String(this.getAlgorithm()); } catch (e) {}
    console.log('[Cipher.init] ' + mode + ' transformation=' + t + ' keyAlg=' + kalg + kfp + ' params=' + params);
    return o.apply(this, args);
  });
  rpc.exports = { reveal: function (on) { REVEAL = !!on; console.log(P + ' reveal=' + REVEAL + (REVEAL ? ' — full key bytes will be printed: capture to $E/sensitive/ only' : '')); return REVEAL; } };
  console.log(P + ' ready: keys print as fingerprints; rpc.exports.reveal(true) for a deliberate capture');
});
