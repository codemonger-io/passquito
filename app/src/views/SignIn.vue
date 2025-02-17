<script setup lang="ts">
import { BButton, BField, BInput } from 'buefy';
import { Base64 } from 'js-base64';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { RouterLink, useRouter } from 'vue-router';

import { useWebauthn } from '../composables/webauthn';
import {
  checkPasskeyAuthenticationSupported,
  doAuthenticationCeremony,
  isAbortError,
} from '../utils/passquito';

// router
const router = useRouter();

// passkey input field which gets focused when mounted.
const passkeyInput = ref<InstanceType<typeof BInput>>();
watch(passkeyInput, (input) => {
  if (input) {
    input.focus();
  }
});

// checks if passkeys are supported. stays `undefined` while checking.
const isPasskeySupported = ref<boolean | undefined>();
onMounted(async () => {
  isPasskeySupported.value = await checkPasskeyAuthenticationSupported();
});

// performs an authentication ceremony if passkeys are supported.
//
// if authenticated, saves the tokens in the local storage and navigates to
// the secured page.
// otherwise, navigates to the sign-up page unless it has been aborted.
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
      if (!isTokens(tokens)) {
        console.error('invalid tokens', tokens);
        throw new Error('invalid tokens');
      }
      console.log('authenticated:', tokens);
      saveTokens(tokens);
      router.push({ name: 'secured' });
    } catch (err) {
      if (!isAbortError(err)) {
        console.error(err);
        router.push({
          name: 'home',
          query: {
            message: 'Failed to authenticate. Would like to register a new passkey?',
          },
        });
      } else {
        console.log('authentication aborted:', err);
      }
    }
  },
  { immediate: true },
);

interface Tokens {
  IdToken: string;
  AccessToken: string;
  RefreshToken: string;
}

function isTokens(value: unknown): value is Tokens {
  if (value == null || typeof value !== 'object') {
    return false;
  }
  const maybeTokens = value as Tokens;
  if (
    typeof maybeTokens.IdToken !== 'string' ||
    typeof maybeTokens.AccessToken !== 'string' ||
    typeof maybeTokens.RefreshToken !== 'string'
  ) {
    return false;
  }
  return true;
}

// saves the tokens in the local storage.
const saveTokens = (tokens: Tokens) => {
  localStorage.setItem('passquitoIdToken', tokens.IdToken);
  localStorage.setItem('passquitoAccessToken', tokens.AccessToken);
  localStorage.setItem('passquitoRefreshToken', tokens.RefreshToken);
};

onBeforeUnmount(() => {
  abortAuthentication.value('leaving page');
});
</script>

<template>
  <main class="container">
    <div v-if="isPasskeySupported" class="login-form">
      <div class="login-form-header">
        <router-link :to="{ name: 'home' }">Sign up</router-link>
      </div>
      <b-field label="Sign in with a passkey">
        <b-input
          ref="passkeyInput"
          autocomplete="username webauthn"
          placeholder="Choose a passkey"
        >
        </b-input>
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

<style scoped>
.login-form {
  .login-form-header {
    display: flex;
    justify-content: flex-end;
    margin-bottom: 1rem;
  }
}
</style>
