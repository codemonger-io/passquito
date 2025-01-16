<script setup lang="ts">
import { BButton, BField, BInput } from 'buefy';
import { onMounted, ref } from 'vue';

import {
  checkPasskeyRegistrationSupported,
  doRegistrationCeremony,
} from '../utils/passquito';

// checks if passkeys are supported 
const isPasskeySupported = ref(false);
onMounted(async () => {
  isPasskeySupported.value = await checkPasskeyRegistrationSupported();
});

const username = ref('');
const displayName = ref('');

// creates a new passkey
const onSubmit = async () => {
  try {
    console.log('starting registration...');
    await doRegistrationCeremony({
      username: username.value,
      displayName: displayName.value,
    });
    console.log('finished registration!');
  } catch(err) {
    console.error(err);
  }
};
</script>

<template>
  <main class="container">
    <form v-if="isPasskeySupported" @submit.prevent="onSubmit">
      <b-field label="Username">
        <b-input v-model="username" pattern="[A-Za-z0-9_:;-]+"></b-input>
      </b-field>
      <b-field label="Display name">
        <b-input v-model="displayName"></b-input>
      </b-field>
      <input type="submit" class="button is-primary" value="Sign Up">
    </form>
    <p v-else>
      Passkeys are not supported on this device.
    </p>
  </main>
</template>
