<script setup lang="ts">
import { BButton, BField, BInput } from 'buefy';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { RouterLink, useRouter } from 'vue-router';

import { useWebauthn } from '../composables/webauthn';
import { useCredentialStore } from '../stores/credential';
import { usePasskeyCapabilityStore } from '../stores/passkey-capability';
import { usePassquitoClientStore } from '../stores/passquito-client';
import { getErrorName } from '../utils/errors';

// router
//
// navigation:
// goes back to the previous page in the history after the user signs in.
const router = useRouter();

// passkey capabilities
const passkeyCapabilityStore = usePasskeyCapabilityStore();

// Passquito client
const passquitoClientStore = usePassquitoClientStore();

// credential
const credentialStore = useCredentialStore();

// passkey input field which gets focused when mounted.
const passkeyInput = ref<InstanceType<typeof BInput>>();
watch(passkeyInput, (input) => {
  if (input) {
    input.focus();
  }
});

// checks if passkey authentication is supported.
onMounted(() => {
  passkeyCapabilityStore.askForCapabilities();
});

// performs an authentication ceremony if passkeys are supported.
//
// if authenticated, saves the tokens in the local storage and navigates to
// the secured page.
// otherwise, navigates to the sign-up page unless it has been aborted.
const abortAuthentication = ref<(message: string) => void>(() => {});
watch(
  () => passkeyCapabilityStore.isAuthenticationSupported,
  async (isSupported) => {
    if (!isSupported) {
      if (!passkeyCapabilityStore.isIndeterminate) {
        console.error("passkeys are not supported on this device");
      }
      return;
    }
    abortAuthentication.value('starting authentication');
    const userId = credentialStore.userId;
    const { abort, credentials: futureCredentials } = userId != null
      ? passquitoClientStore.client.doAuthenticationCeremonyForUser(userId)
      : passquitoClientStore.client.doAuthenticationCeremony();
    abortAuthentication.value = abort;
    try {
      const { publicKeyInfo, tokens } = await futureCredentials;
      console.log('authenticated:', publicKeyInfo, tokens);
      credentialStore.savePublicKeyInfo(publicKeyInfo);
      credentialStore.saveTokens(tokens);
      router.back();
    } catch (err) {
      switch (getErrorName(err)) {
        case 'AbortError':
          console.log('authentication aborted:', err);
          break;
        case 'NotAllowedError':
          console.error(err);
          router.push({
            name: 'home',
            query: {
              message: 'Failed to authenticate. The credential request was denied or sent to a wrong relying party.',
            },
          });
          break;
        default:
          console.error(err);
          router.push({
            name: 'home',
            query: {
              message: 'Failed to authenticate. Would like to register a new passkey?',
            },
          });
      }
    }
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  abortAuthentication.value('leaving page');
});
</script>

<template>
  <main class="container">
    <div v-if="passkeyCapabilityStore.isAuthenticationSupported" class="login-form">
      <div class="login-form-header">
        <router-link :to="{ name: 'home' }">Sign up</router-link>
      </div>
      <b-field label="Sign in with a passkey">
        <b-input
          ref="passkeyInput"
          autocomplete="username webauthn"
          placeholder="Choose a passkey"
        >
        </b-input>
      </b-field>
    </div>
    <p v-else-if="passkeyCapabilityStore.isIndeterminate">
      Checking if passkey authentication is supported on this device...
    </p>
    <p v-else>
      Passkey authentication is not supported on this device.
    </p>
  </main>
</template>

<style scoped>
.login-form {
  .login-form-header {
    display: flex;
    justify-content: flex-end;
    margin-bottom: 1rem;
  }
}
</style>
