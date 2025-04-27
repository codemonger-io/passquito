import { defineStore } from 'pinia';
import { computed } from 'vue';

import { PassquitoClient } from '../utils/passquito-client';

import { useCredentialsApiStore } from './credentials-api';

export const usePassquitoClientStore = defineStore('passquito-client', () => {
  // Credentials API access
  const credentialsApiStore = useCredentialsApiStore();
  const api = computed(() => credentialsApiStore.api);

  // Passquito client
  const client = computed(() => new PassquitoClient(api.value));

  return {
    api,
    client,
  };
});
