<script setup lang="ts">
import { BNotification } from 'buefy';
import { onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import { credentialsApiUrl } from '../auth-config';

// router
const router = useRouter();

// loads the ID token from the local storage.
//
// NOTE: AWS APIGateway REST API cannot verify access tokens but can verify
// only ID tokens.
const idToken = ref<string | null>(null);
onMounted(() => {
  try {
    idToken.value = localStorage.getItem('passquitoIdToken');
  } catch (err) {
    console.error(err);
  }
});

const STATUS_CODES = ['OK', 'Unauthorized', 'Error'];
type StatusCode = typeof STATUS_CODES[number];

// requests a new device invitation URL when the ID token is ready.
const invitationUrl = ref<string | undefined>();
const lastStatus = ref<StatusCode>('OK');
watch(idToken, async (token) => {
  if (token == null) {
    return;
  }
  invitationUrl.value = undefined;
  const url = `${credentialsApiUrl}registration/invite`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: token
      }
    });
    switch (res.status) {
      case 200:
        const sessionId = readSessionId(await res.json());
        invitationUrl.value = router.resolve({
          name: 'register-device',
          params: { sessionId }
        }).href;
        lastStatus.value = 'OK';
        break;
      case 401:
        lastStatus.value = 'Unauthorized';
        break;
      default:
        console.error('failed to request an invitation URL:', res.status);
        lastStatus.value = 'Error';
    }
  } catch (err) {
    console.error(err);
    lastStatus.value = 'Error';
  }
});

const readSessionId = (contents: unknown): string => {
  console.log('reading invitation session info:', contents);
  if (contents == null || typeof contents !== 'object') {
    throw new Error('invitation session info must be an object');
  }
  const { sessionId } = (contents as { sessionId: string });
  if (typeof sessionId !== 'string') {
    throw new Error('invitation session ID must have a string');
  }
  return sessionId;
};
</script>

<template>
  <main class="container">
    <template v-if="idToken">
      <div v-if="invitationUrl" class="has-text-centered">
        <p>{{ invitationUrl }}</p>
        <b-notification type="is-warning" :closable="false">
          DO NOT share this URL with others!
        </b-notification>
      </div>
      <p v-else-if="lastStatus === 'Unauthorized'">
        Unauthorized!
        Please <a :href="router.resolve({ name: 'signin' }).href">sign in</a> again.
      </p>
      <p v-else-if="lastStatus !== 'OK'">Error!</p>
      <p v-else>Requesting an invitation URL...</p>
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
