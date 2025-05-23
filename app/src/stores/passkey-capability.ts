import { defineStore } from 'pinia';
import { ref } from 'vue';

import {
  checkPasskeyAuthenticationSupported,
  checkPasskeyRegistrationSupported,
} from '@codemonger-io/passquito-client-js';

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
    // no capabilities by default
    isAuthenticationSupported.value = false;
    isRegistrationSupported.value = false;
    try {
      isAuthenticationSupported.value = await checkPasskeyAuthenticationSupported();
      isRegistrationSupported.value = await checkPasskeyRegistrationSupported();
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
