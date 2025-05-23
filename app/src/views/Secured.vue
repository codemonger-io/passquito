<script setup lang="ts">
import { BButton, BMessage } from 'buefy';
import { onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import { credentialsApiUrl } from '../auth-config';
import { useCredentialStore } from '../stores/credential';
import { useCredentialsApiStore } from '../stores/credentials-api';

// router
const router = useRouter();

// Credentials API access
const credentialsApiStore = useCredentialsApiStore();

// credential
const credentialStore = useCredentialStore();

// requires the credential
onMounted(() => {
  credentialStore.askForCredential();
});

// redirects to the sign-in page if the user is not authenticated.
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

const STATUS_CODES = ['OK', 'Unauthorized', 'Error'];
type StatusCode = typeof STATUS_CODES[number];

// refreshes tokens
//
// returns if tokens are successfully refreshed.
// may throw an error.
const refreshTokens = async () => {
  console.log('refreshing tokens...');
  const refreshToken = credentialStore.refreshToken;
  if (refreshToken == null) {
    return false;
  }
  const newTokens = await credentialsApiStore.api.refreshTokens(refreshToken);
  if (newTokens == null) {
    return false;
  }
  console.log('refreshed tokens:', newTokens);
  credentialStore.saveTokens(newTokens);
  return true;
};

// obtains the secured message when the ID token is ready.
const securedMessage = ref<string | undefined>();
const lastStatus = ref<StatusCode>('OK');
watch(
  () => credentialStore.idToken,
  async (token) => {
    if (token == null) {
      return;
    }
    securedMessage.value = undefined;
    // refreshes tokens if they are expiring or expired.
    if (credentialStore.shouldRefreshTokens()) {
      try {
        if (!await refreshTokens()) {
          lastStatus.value = 'Unauthorized';
          return;
        }
        // this watcher will be triggered again with the new ID token
        return;
      } catch (err) {
        console.error(err);
        lastStatus.value = 'Error';
        return;
      }
    }
    const url = `${credentialsApiUrl}secured`;
    try {
      const res = await fetch(url, {
        headers: {
          Authorization: token
        }
      });
      switch (res.status) {
        case 200:
          securedMessage.value = readSecuredMessage(await res.json());
          lastStatus.value = 'OK';
          break;
        case 401:
          lastStatus.value = 'Unauthorized';
          break;
        default:
          console.error('failed to obtain the secured message:', res.status);
          lastStatus.value = 'Error';
      }
    } catch (err) {
      console.error(err);
      lastStatus.value = 'Error';
    }
  },
  { immediate: true }
);

const readSecuredMessage = (contents: unknown): string => {
  console.log('reading secured message:', contents);
  if (contents == null || typeof contents !== 'object') {
    throw new Error('secured contents must be an object');
  }
  const message = (contents as { message: string }).message;
  if (typeof message !== 'string') {
    throw new Error('secured contents must have a message string');
  }
  return message;
};

const registerThisDevice = () => {
  router.push({ name: 'register-device' });
};
</script>

<template>
  <main class="container">
    <template v-if="credentialStore.idToken">
      <div>
        <div v-if="securedMessage">
          <div class="has-text-centered">
            <p>{{ securedMessage }}</p>
          </div>
          <section v-if="credentialStore.isCrossDevice" class="section">
            <div class="panel is-info">
              <div class="panel-heading">
                Cross-device authentication detected
              </div>
              <div class="panel-block">
                <p>
                  You look beeing authenticated from another device.
                  Would you like to register this device?
                </p>
              </div>
              <div class="panel-block">
                <b-button
                  type="is-info"
                  @click="registerThisDevice"
                  expanded
                  outlined
                >
                  Register this device
                </b-button>
              </div>
            </div>
          </section>
        </div>
        <p v-else-if="lastStatus === 'Unauthorized'">
          Unauthorized!
          Please <a :href="router.resolve({ name: 'signin' }).href">sign in</a> again.
        </p>
        <p v-else-if="lastStatus !== 'OK'">Error!</p>
        <p v-else>Obtaining the secured contents...</p>
      </div>
    </template>
    <div v-else>
      <p>
        You have to
        <a :href="router.resolve({ name: 'signin' }).href">sign in</a>
        first.
      </p>
    </div>
  </main>
</template>
