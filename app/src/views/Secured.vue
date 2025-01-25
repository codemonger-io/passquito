<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import { credentialsApiUrl } from '../auth-config';

// router
const router = useRouter();

// loads the access token from the local storage
const accessToken = ref<string | null>(null);
onMounted(() => {
  try {
    accessToken.value = localStorage.getItem('passquitoAccessToken');
  } catch (err) {
    console.error(err);
  }
});

const STATUS_CODES = ['OK', 'Unauthorized', 'Error'];
type StatusCode = typeof STATUS_CODES[number];

// obtains the secured message when the access token is ready.
const securedMessage = ref<string | undefined>();
const lastStatus = ref<StatusCode>('OK');
watch(accessToken, async (token) => {
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
    <template v-if="accessToken">
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
