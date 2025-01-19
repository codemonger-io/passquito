<script setup lang="ts">
import { BButton, BField, BInput } from 'buefy';
import { Base64 } from 'js-base64';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';

import { useWebauthn } from '../composables/webauthn';
import {
  checkPasskeyAuthenticationSupported,
  doAuthenticationCeremony,
} from '../utils/passquito';

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
      console.error(err);
      // reloads to show the conditional UI again
      // TODO: should we rather navigate to the sign-up page?
      window.location.reload();
    }
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  abortAuthentication.value('leaving page');
});
</script>

<template>
  <main>
    <div v-if="isPasskeySupported">
      <b-field label="Username">
        <b-input name="username" autocomplete="username webauthn"></b-input>
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
