<script setup lang="ts">
import { BButton, BField, BInput } from 'buefy';
import { Base64 } from 'js-base64';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { RouterLink, useRouter } from 'vue-router';

import { useWebauthn } from '../composables/webauthn';
import {
  checkPasskeyAuthenticationSupported,
  doAuthenticationCeremony,
  isAbortError,
} from '../utils/passquito';

// router
const router = useRouter();

// passkey input field
const passkeyInput = ref<InstanceType<typeof BInput>>();

// checks if passkeys are supported. stays `undefined` while checking.
const isPasskeySupported = ref<boolean | undefined>();
onMounted(async () => {
  isPasskeySupported.value = await checkPasskeyAuthenticationSupported();
});

// requests conditional mediation if passkeys are supported
const abortAuthentication = ref<(message: string) => void>(() => {});
watch(
  isPasskeySupported,
  async (isSupported) => {
    if (isSupported === undefined) {
      return; // loading
    }
    if (!isSupported) {
      console.error("passkeys are not supported on this device");
      return;
    }
    abortAuthentication.value('starting authentication');
    const { abort, tokens: futureTokens } = doAuthenticationCeremony();
    abortAuthentication.value = abort;
    try {
      const tokens = await futureTokens;
      console.log('authenticated:', tokens);
      alert('authenticated!');
    } catch (err) {
      // navigates to the sign-up page unless it is aborted
      if (!isAbortError(err)) {
        console.error(err);
        router.push({
          name: 'home',
          query: {
            message: 'Failed to authenticate. Would like to register a new passkey?',
          },
        });
      } else {
        console.log('authentication aborted:', err);
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
    <div v-if="isPasskeySupported" class="login-form">
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
    <p v-else-if="isPasskeySupported === undefined">
      Checking if passkeys are supported on this device...
    </p>
    <p v-else>
      Passkeys are not supported on this device.
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
