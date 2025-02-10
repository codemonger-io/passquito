<script setup lang="ts">
import { BField, BInput } from 'buefy';
import { onMounted, ref, watch } from 'vue';

import {
  checkPasskeyRegistrationSupported,
  doInvitedRegistrationCeremony
} from '../utils/passquito';

const props = defineProps<{
  sessionId: string
}>();

// checks if passkeys are supported
const isPasskeySupported = ref(false);
onMounted(async () => {
  isPasskeySupported.value = await checkPasskeyRegistrationSupported();
});

const username = ref('');
const displayName = ref('');

// registers a new device (credential)
const onSubmit = async () => {
  try {
    console.log('starting registration...');
    await doInvitedRegistrationCeremony({
      username: username.value,
      displayName: displayName.value,
      invitationSessionId: props.sessionId
    });
    console.log('finished registration!');
  } catch (err) {
    console.error(err);
  }
}
</script>

<template>
  <main class="container">
    <div v-if="isPasskeySupported" class="login-form">
      <form @submit.prevent="onSubmit">
        <b-field label="Username">
          <b-input v-model="username" pattern="[A-Za-z0-9_:;-]+"></b-input>
        </b-field>
        <b-field label="Display name">
          <b-input v-model="displayName"></b-input>
        </b-field>
        <input type="submit" class="button is-primary" value="Register">
      </form>
    </div>
    <p v-else>
      Passkeys are not supported on this device.
    </p>
  </main>
</template>
