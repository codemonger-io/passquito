import { defineStore } from 'pinia';
import { ref } from 'vue';

export const usePasskeyCapabilityStore = defineStore('passkey-capability', () => {
  // whether capabilities are indeterminate
  // (not asked for, or being asked for)
  const isIndeterminate = ref<boolean>(true);

  // whether passkey authentication is supported
  const isAuthenticationSupported = ref<boolean>(false);

  // whether passkey registration is supported
  const isRegistrationSupported = ref<boolean>(false);

  // asks for capabilities
  // does nothing if capabilities are already known.
  // TODO: option to ask for capabilities again?
  const _isAskingForCapabilities = ref<boolean>(false);
  const askForCapabilities = async () => {
    if (_isAskingForCapabilities.value) {
      console.log('already asking for passkey capabilities');
      return;
    }
    if (!isIndeterminate.value) {
      console.log('already asked for passkey capabilities');
      console.log('authentication:', isAuthenticationSupported.value);
      console.log('registration:', isRegistrationSupported.value);
      return;
    }
    _isAskingForCapabilities.value = true;
    // authentication is available if a conditional mediation is available
    // registration is available if both conditional mediation and user
    // verifying platform authenticator are available
    // no capabilities by default
    isAuthenticationSupported.value = false;
    isRegistrationSupported.value = false;
    try {
      if (!window.PublicKeyCredential) {
        console.warn('no PublicKeyCredential');
        return;
      }
      // asks the authentication capability
      if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
        console.warn('no isConditionalMediationAvailable');
        return;
      }
      isAuthenticationSupported.value =
        await window.PublicKeyCredential.isConditionalMediationAvailable();
      if (!isAuthenticationSupported.value) {
        console.warn('not isConditionalMediationAvailable');
        return;
      }
      // asks the registration capability
      if (typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
        console.warn('no isUserVerifyingPlatformAuthenticatorAvailable');
        return;
      }
      isRegistrationSupported.value =
        await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!isRegistrationSupported.value) {
        console.warn('not isUserVerifyingPlatformAuthenticatorAvailable');
        return;
      }
    } catch (err) {
      console.error(err);
    } finally {
      _isAskingForCapabilities.value = false;
      isIndeterminate.value = false;
    }
  };

  return {
    askForCapabilities,
    isAuthenticationSupported,
    isIndeterminate,
    isRegistrationSupported,
    _isAskingForCapabilities,
  };
});
