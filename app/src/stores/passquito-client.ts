import { defineStore } from 'pinia';
import { ref } from 'vue';

import { PassquitoClient } from '@codemonger-io/passquito-client-js';

import { useCredentialsApiStore } from './credentials-api';

export const usePassquitoClientStore = defineStore('passquito-client', () => {
  // Credentials API access
  const credentialsApiStore = useCredentialsApiStore();

  // Passquito client
  const client = ref(new PassquitoClient(credentialsApiStore.api));

  return {
    client,
  };
});
