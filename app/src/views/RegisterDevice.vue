<script setup lang="ts">
import { BField, BInput } from 'buefy';
import { onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import { useCredentialStore } from '../stores/credential';
import { useCredentialsApiStore } from '../stores/credentials-api';
import { usePasskeyCapabilityStore } from '../stores/passkey-capability';
import {
  doRegistrationCeremonyForVerifiedUser,
  getErrorName,
} from '../utils/passquito';

// router
const router = useRouter();

// passeky capabilities
const passkeyCapabilityStore = usePasskeyCapabilityStore();

// checks if passkeys are supported
onMounted(() => {
  passkeyCapabilityStore.askForCapabilities();
});

// credentials API access
const credentialsApiStore = useCredentialsApiStore();

// credential
const credentialStore = useCredentialStore();

// requires the credential
onMounted(() => {
  credentialStore.askForCredential();
});

// redirects to the sign-in page if the user is not authenticated
watch(
  () => credentialStore.state,
  (state) => {
    if (state === 'unauthenticated') {
      console.log('redirecting to the sign-in page...');
      window.location.href = router.resolve({ name: 'signin' }).href;
    }
  },
  { immediate: true }
);

// username and display name which are updated whenever those associated with
// the credential change
const username = ref('');
const displayName = ref('');

watch(() => credentialStore.username, (newUsername) => {
  newUsername = newUsername ?? '';
  if (username.value !== newUsername) {
    username.value = newUsername;
  }
});
watch(() => credentialStore.displayName, (newDisplayName) => {
  newDisplayName = newDisplayName ?? '';
  if (displayName.value !== newDisplayName) {
    displayName.value = newDisplayName
  }
});

// registers a new device (credential)
const onSubmit = async () => {
  const idToken = credentialStore.idToken;
  if (idToken == null) {
    console.error('no ID token is available.');
    return;
  }
  try {
    console.log('starting registration...');
    // TODO: deal with a token expiration
    await doRegistrationCeremonyForVerifiedUser(
      credentialsApiStore.api,
      {
        idToken,
        userInfo: {
          username: username.value,
          displayName: displayName.value,
        }
      },
    );
    console.log('finished registration!');
  } catch (err) {
    if (getErrorName(err) === 'InvalidStateError') {
      console.error('you already have a credential on this device.');
    } else {
      console.error(err);
    }
  }
}
</script>

<template>
  <main class="container">
    <template v-if="credentialStore.state === 'authenticated'">
      <div v-if="passkeyCapabilityStore.isRegistrationSupported" class="login-form">
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
    </template>
    <p v-else-if="credentialStore.state === 'indeterminate'">
      Checking if authenticated...
    </p>
    <p v-else>
      You have to
      <a :href="router.resolve({ name: 'signin' }).href">sign in</a>
      first.
    </p>
  </main>
</template>
