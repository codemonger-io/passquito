<script setup lang="ts">
import { BButton, BField, BInput, BNotification } from 'buefy';
import { computed, onMounted, ref } from 'vue';
import { RouterLink, useRouter } from 'vue-router';

import { useCredentialStore } from '../stores/credential';
import { usePasskeyCapabilityStore } from '../stores/passkey-capability';
import { usePassquitoClientStore } from '../stores/passquito-client';

defineProps({
  message: String
});

// router
//
// navigation:
// navigates to the secured page after the user signs up.
// the user will be required to sign in.
const router = useRouter();

// passkey capabilities
const passkeyCapabilityStore = usePasskeyCapabilityStore();

// Passquito client
const passquitoClientStore = usePassquitoClientStore();

// credential
const credentialStore = useCredentialStore();

// checks if passkeys are supported 
onMounted(async () => {
  passkeyCapabilityStore.askForCapabilities();
});

const username = ref('');
const displayName = ref('');

// creates a new passkey
const onSubmit = async () => {
  try {
    console.log('starting registration...');
    const publicKeyInfo = await passquitoClientStore.client.doRegistrationCeremony({
      username: username.value,
      displayName: displayName.value,
    });
    console.log('finished registration!', publicKeyInfo);
    credentialStore.savePublicKeyInfo(publicKeyInfo);
    router.push({ name: 'secured' });
  } catch(err) {
    console.error(err);
  }
};
</script>

<template>
  <main class="container">
    <div v-if="passkeyCapabilityStore.isRegistrationSupported" class="login-form">
      <div class="login-form-header" style="font-size: 1rem;">
        <div class="is-flex is-justify-content-end">
          <a :href="router.resolve({ name: 'signin' }).href">Sign in</a>
        </div>
        <div>
          <b-notification v-if="message" type="is-warning" role="alert">
            {{ message }}
          </b-notification>
        </div>
      </div>
      <form @submit.prevent="onSubmit">
        <b-field label="Username">
          <b-input v-model="username" pattern="[A-Za-z0-9_:;-]+"></b-input>
        </b-field>
        <b-field label="Display name">
          <b-input v-model="displayName"></b-input>
        </b-field>
        <input type="submit" class="button is-primary" value="Sign up">
      </form>
    </div>
    <p v-else>
      Passkey registration is not supported on this device.
    </p>
  </main>
</template>

<style scoped>
.login-form {
  .login-form-header {
    margin-bottom: 1rem;
  }
}
</style>
