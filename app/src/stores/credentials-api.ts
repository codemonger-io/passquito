import { defineStore } from 'pinia';
import { ref } from 'vue';

import { credentialsApiUrl } from '../auth-config';
import { CredentialsApiImpl } from '../utils/credentials-api-impl';

export const useCredentialsApiStore = defineStore('credentials-api', () => {
  // credentials API
  const api = ref(new CredentialsApiImpl(credentialsApiUrl));

  return {
    api,
  };
});
