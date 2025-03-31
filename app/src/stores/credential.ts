import { StorageSerializers, useStorage } from '@vueuse/core';
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

import { type CognitoTokens, isCognitoTokens } from '../utils/passquito';
import { makeValidatingSerializer } from '../utils/serializer';

// possible states of the credential.
// - "indeterminate": initial state
// - "authenticated": authenticated and the ID token should be available
// - "unauthenticated": authentication attempt has failed
//
// TODO: should we add "authenticating" state?
export type CredentialState =
  | 'indeterminate'
  | 'authenticated'
  | 'unauthenticated';

/**
 * Minimum refresh interval of ID and access tokens in milliseconds.
 *
 * @remarks
 *
 * To prevent tokens from being refreshed too frequently.
 * You should configure the duration of tokens longer than this value plus
 * `TOKEN_REFRESH_MARGIN_IN_MS`.
 *
 * @beta
 */
export const MIN_TOKEN_REFRESH_INTERVAL_IN_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Margin period in milliseconds for refreshing ID and access tokens before
 * they expire.
 *
 * @remarks
 *
 * To mitigate the risk of getting unauthorized errors due to expired tokens.
 * You should configure the duration of tokens longer than this value plus
 * `MIN_TOKEN_REFRESH_INTERVAL_IN_MS`.
 *
 * @beta
 */
export const TOKEN_REFRESH_MARGIN_IN_MS = 2 * 60 * 1000; // 2 minutes

export const useCredentialStore = defineStore('credential', () => {
  // current state
  const state = ref<CredentialState>('indeterminate');

  // Cogito tokens which are persisted
  const tokens = useStorage<CognitoTokens>(
    'passquitoTokens',
    null,
    undefined,
    {
      // explicit serializer is required if the default is null
      // https://vueuse.org/core/useStorage/#custom-serialization
      serializer: makeValidatingSerializer(isCognitoTokens),
    }
  );

  // ID token
  // NOTE: `null` unless the state is 'authenticated'
  //       check `state` prior to using this value to avoid a glitch in UI.
  const idToken = computed(() => {
    if (state.value !== 'authenticated') {
      return null;
    }
    return tokens.value?.idToken;
  });

  // refresh token
  // NOTE: `null` unless the state is 'authenticated'
  //       check `state` prior to using this value to avoid a glitch in UI.
  const refreshToken = computed(() => {
    if (state.value !== 'authenticated') {
      return null;
    }
    return tokens.value?.refreshToken;
  });

  // time to refresh the ID and access tokens.
  // NOTE: `null` if tokens are unavailable.
  const timeToRefreshTokens = computed(() => {
    const activatedAt = tokens.value?.activatedAt;
    const expiresIn = tokens.value?.expiresIn;
    if (activatedAt == null || expiresIn == null) {
      return null;
    }
    const expiresAt = activatedAt + expiresIn * 1000;
    return Math.max(
      activatedAt + MIN_TOKEN_REFRESH_INTERVAL_IN_MS,
      expiresAt - TOKEN_REFRESH_MARGIN_IN_MS,
    );
  });

  // if the ID and access tokens should be refreshed.
  // NOTE: `false` if tokens are unavailable.
  const shouldRefreshTokens = () => {
    const timeToRefresh = timeToRefreshTokens.value;
    if (timeToRefresh == null) {
      return false;
    }
    return Date.now() >= timeToRefresh;
  };

  // username associated with the current credential
  // TODO: obtain from the credential
  const username = ref<string | undefined>();
  // display name associated with the current credential
  // TODO: obtain from the credential
  const displayName = ref<string | undefined>();

  // whether the credential is authenticated in a cross-device manner
  // TODO: obtain from the credential
  const isCrossDevice = ref<boolean>(true);

  // asks for the credential.
  //
  // after calling this function, the ID token will be available if the
  // credential is authenticated.
  //
  // if the credential is not authenticated, it will request an authentication.
  const askForCredential = () => {
    switch (state.value) {
      case 'authenticated':
        console.log('credential has already been authenticated');
        return;
      case 'unauthenticated':
        // TODO: queue a request event for an authentication
        return;
      case 'indeterminate':
        if (tokens.value != null) {
          console.log('tokens', tokens.value);
          state.value = 'authenticated';
        } else {
          // TODO: queue a request event for an authentication
          state.value = 'unauthenticated';
        }
        break;
      default: {
        const _never: never = state.value;
        console.error(`unexpected state: ${_never}`);
      }
    }
  };

  // saves given Cognito tokens.
  // also updates `state`:
  // → 'authenticated' if `newTokens` is not null
  // → 'unauthenticated' if `newTokens` is null
  const saveTokens = (newTokens: CognitoTokens | null) => {
    if (newTokens == null) {
      state.value = 'unauthenticated';
    }
    tokens.value = newTokens;
    if (newTokens != null) {
      state.value = 'authenticated';
    }
  };

  return {
    askForCredential,
    displayName,
    idToken,
    isCrossDevice,
    refreshToken,
    saveTokens,
    shouldRefreshTokens,
    state,
    timeToRefreshTokens,
    username,
  };
});
