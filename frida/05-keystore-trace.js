/* 05-keystore-trace.js — D12/D13: KeyGenParameterSpec as actually BUILT, and whether a biometric gate is real.
 * REMEMBER: isInsideSecureHardware()==false is an EMULATOR ARTEFACT. Never report it.
 *
 * Run      spawn:  frida -D $ANDROID_SERIAL -f <pkg> -l frida/05-keystore-trace.js -t 120 -q | tee $E/logs/frida-05-$(date +%s).log
 *          Key generation usually happens once (first login / enrolment): spawn after `pm clear <pkg>` or the builder
 *          hooks never fire. The authenticate() hooks fire on every prompt and work in attach mode.
 *
 * What is hooked
 *   KeyGenParameterSpec$Builder setters (all overloads) incl. setUserAuthenticationParameters (API 30+) and
 *   Builder.build(): the BUILT spec is read back (isUserAuthenticationRequired, validity seconds, auth type,
 *   isInvalidatedByBiometricEnrollment, isUnlockedDeviceRequired, isStrongBoxBacked) — what was built, not what was
 *   called.
 *   androidx.biometric.BiometricPrompt.authenticate, android.hardware.biometrics.BiometricPrompt.authenticate and
 *   FingerprintManager.authenticate: the CryptoObject argument is located BY TYPE in each overload, so a prompt with
 *   no CryptoObject (a boolean an attacker can force) is told apart from one bound to a Keystore key.
 *   Classes are resolved through every class loader (dynamic-feature / delegate loaders) before absence is printed,
 *   and absence is printed as [05][UNVERIFIED], never as "not present".
 *
 * Zero result means
 *  - "[05][UNVERIFIED] class not found in any loader" = the library is not loaded in this process (yet). A negative
 *    for "no biometric gate" needs the static read of $DEC (androidx.biometric, BiometricPrompt, FingerprintManager).
 *  - builder lines absent in attach mode = the key already existed; `pm clear` and spawn.
 *  - authenticate lines absent = no prompt was shown while attached: exercise the gated screen. */
'use strict';
var P = '[05]';
function unverified(m) { console.log(P + '[UNVERIFIED] ' + m); }
function use(name) {
  try { return Java.use(name); } catch (e0) {
    var loaders = []; try { loaders = Java.enumerateClassLoadersSync(); } catch (e1) {}
    for (var i = 0; i < loaders.length; i++) {
      try { loaders[i].loadClass(name); return Java.ClassFactory.get(loaders[i]).use(name); } catch (e2) {}
    }
    unverified('class not found in any loader (' + loaders.length + ' enumerated): ' + name);
    return null;
  }
}
function hookAll(C, method, cb) {
  if (!C) return;
  try {
    if (!C[method]) { unverified(C.$className + '.' + method + ' not present on this build'); return; }
    C[method].overloads.forEach(function (o) {
      try { o.implementation = function () { return cb.call(this, o, arguments); }; }
      catch (e) { unverified('hook ' + C.$className + '.' + method + ' overload failed: ' + e); }
    });
  } catch (e) { unverified('hook ' + C.$className + '.' + method + ' failed: ' + e); }
}
function argOfType(o, args, re) { for (var i = 0; i < o.argumentTypes.length; i++) if (re.test(o.argumentTypes[i].className)) return args[i]; return undefined; }
function authLine(who, o, args) {
  var crypto = argOfType(o, args, /CryptoObject$/);
  console.log('\n[' + who + '.authenticate] CryptoObject=' + (crypto === undefined ? 'no such parameter in this overload' : crypto));
  if (!crypto) console.log('   !! NO CryptoObject -> the result is a BOOLEAN an attacker can force (CANDIDATE D13: UI-only biometric gate)');
  else {
    console.log('   -> bound to a Keystore key: the gate is real IF the key was built with setUserAuthenticationRequired(true) (see the builder lines)');
    try { console.log('   cipher=' + crypto.getCipher() + ' signature=' + crypto.getSignature() + ' mac=' + crypto.getMac()); } catch (e) {}
  }
  try { send({ script: '05-keystore-trace', ev: 'authenticate', who: who, cryptoObject: !!crypto, tag: crypto ? '' : 'CANDIDATE', items: ['D13-001'] }); } catch (e) {}
}
Java.perform(function () {
  var B = use('android.security.keystore.KeyGenParameterSpec$Builder');
  ['setUserAuthenticationRequired', 'setInvalidatedByBiometricEnrollment', 'setUnlockedDeviceRequired', 'setIsStrongBoxBacked',
   'setUserAuthenticationValidityDurationSeconds', 'setUserAuthenticationParameters', 'setUserConfirmationRequired', 'setRandomizedEncryptionRequired']
  .forEach(function (m) {
    if (!B || !B[m]) return;                 // setters absent on older API levels are not an error
    hookAll(B, m, function (o, args) {
      var a = []; for (var i = 0; i < args.length; i++) a.push(String(args[i]));
      console.log('[KeyGenParameterSpec.Builder] ' + m + '(' + a.join(', ') + ')' + (m === 'setUserAuthenticationParameters' ? '  (timeout s, type: 1=BIOMETRIC_STRONG 2=DEVICE_CREDENTIAL 3=both)' : ''));
      return o.apply(this, args);
    });
  });
  hookAll(B, 'build', function (o, args) {
    var spec = o.apply(this, args);
    try {
      var line = '[KeyGenParameterSpec.build] alias=' + spec.getKeystoreAlias() + ' purposes=' + spec.getPurposes()
        + ' userAuthRequired=' + spec.isUserAuthenticationRequired()
        + ' validitySeconds=' + spec.getUserAuthenticationValidityDurationSeconds() + ' (-1 = every use, >0 = time window)';
      try { line += ' authType=' + spec.getUserAuthenticationType(); } catch (e) {}
      try { line += ' invalidatedByEnrollment=' + spec.isInvalidatedByBiometricEnrollment(); } catch (e) {}
      try { line += ' unlockedDeviceRequired=' + spec.isUnlockedDeviceRequired(); } catch (e) {}
      try { line += ' strongBox=' + spec.isStrongBoxBacked(); } catch (e) {}
      console.log(line);
      if (!spec.isUserAuthenticationRequired()) console.log('   -> key is NOT auth-bound: any biometric prompt around it is UI only (CANDIDATE D13)');
      try { send({ script: '05-keystore-trace', ev: 'build', alias: String(spec.getKeystoreAlias()), userAuthRequired: spec.isUserAuthenticationRequired(), tag: spec.isUserAuthenticationRequired() ? '' : 'CANDIDATE', items: ['D12-010', 'D13-001'] }); } catch (e) {}
    } catch (e) { unverified('reading the built spec failed: ' + e); }
    return spec;
  });
  hookAll(use('androidx.biometric.BiometricPrompt'), 'authenticate', function (o, args) { authLine('androidx.biometric.BiometricPrompt', o, args); return o.apply(this, args); });
  hookAll(use('android.hardware.biometrics.BiometricPrompt'), 'authenticate', function (o, args) { authLine('android.hardware.biometrics.BiometricPrompt', o, args); return o.apply(this, args); });
  hookAll(use('android.hardware.fingerprint.FingerprintManager'), 'authenticate', function (o, args) { authLine('FingerprintManager', o, args); return o.apply(this, args); });
  console.log(P + ' ready: builder + build() + three authenticate() entry points hooked (absent classes were reported above)');
});
