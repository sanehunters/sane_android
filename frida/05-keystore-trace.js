/* D12/D13 — KeyGenParameterSpec as actually built, and whether a biometric gate is real.
 * REMEMBER: isInsideSecureHardware()==false is an EMULATOR ARTEFACT. Never report it. */
Java.perform(function () {
  try {
    var B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
    ['setUserAuthenticationRequired','setInvalidatedByBiometricEnrollment',
     'setUnlockedDeviceRequired','setIsStrongBoxBacked','setUserAuthenticationValidityDurationSeconds']
    .forEach(function (m) {
      if (!B[m]) return;
      B[m].overloads.forEach(function (o) {
        o.implementation = function () {
          console.log('[KeyGenParameterSpec] ' + m + '(' + arguments[0] + ')');
          return o.apply(this, arguments);
        };
      });
    });
  } catch (e) {}
  try {
    var BP = Java.use('androidx.biometric.BiometricPrompt');
    BP.authenticate.overloads.forEach(function (o) {
      o.implementation = function () {
        var crypto = arguments.length > 1 ? arguments[1] : null;
        console.log('\n[BiometricPrompt.authenticate] CryptoObject=' + crypto);
        if (!crypto)
          console.log('   !! NO CryptoObject -> the result is a BOOLEAN an attacker can force.');
        else
          console.log('   -> bound to a Keystore key: the gate is real');
        return o.apply(this, arguments);
      };
    });
  } catch (e) { console.log('[skip] androidx.biometric not present'); }
});
