<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

// router
const router = useRouter();

// loads the access token from the local storage
const accessToken = ref<string | undefined>();
onMounted(() => {
  try {
    accessToken.value = localStorage.getItem('passquitoAccessToken');
  } catch (err) {
    console.error(err);
  }
});
</script>

<template>
  <main class="container">
    <div v-if="accessToken">
      <p>Secured!</p>
    </div>
    <div v-else>
      <p>
        You have to
        <a :href="router.resolve({ name: 'signin' }).href">sign in</a>
        first.
      </p>
    </div>
  </main>
</template>
