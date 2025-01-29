<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import { credentialsApiUrl } from '../auth-config';

// router
const router = useRouter();

// loads the ID token from the local storage
//
// NOTE: AWS APIGateway REST API can not verify access tokens but can verify
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

// obtains the secured message when the ID token is ready.
const securedMessage = ref<string | undefined>();
const lastStatus = ref<StatusCode>('OK');
watch(idToken, async (token) => {
  if (token == null) {
    return;
  }
  securedMessage.value = undefined;
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
});

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
</script>

<template>
  <main class="container">
    <template v-if="idToken">
      <div>
        <p v-if="securedMessage">{{ securedMessage }}</p>
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
