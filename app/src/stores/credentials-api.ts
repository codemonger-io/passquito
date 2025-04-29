import { defineStore } from 'pinia';
import { ref } from 'vue';

import { CredentialsApiImpl } from '@codemonger-io/passquito-client-js';

import { credentialsApiUrl } from '../auth-config';

export const useCredentialsApiStore = defineStore('credentials-api', () => {
  // credentials API
  const api = ref(new CredentialsApiImpl(credentialsApiUrl));

  return {
    api,
  };
});
