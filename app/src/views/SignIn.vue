<script setup lang="ts">
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { Base64 } from 'js-base64';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';

import { credentialsApiUrl, userPoolClientId } from '../auth-config';
import { useWebauthn } from '../composables/webauthn';

const cognitoClient = new CognitoIdentityProviderClient({
  region: 'ap-northeast-1',
});

// checks if passkeys are supported.
// references:
// - https://web.dev/articles/passkey-form-autofill
// - https://www.w3.org/TR/webauthn-3/
const isPasskeySupported = ref<boolean | undefined>();
onMounted(async () => {
  if (!window.PublicKeyCredential) {
    console.error('no PublicKeyCredential');
    isPasskeySupported.value = false;
    return;
  }
  if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
    console.error('no PublicKeyCredential.isConditionalMediationAvailable');
    isPasskeySupported.value = false;
    return;
  }
  try {
    const isConditionalMediationAvailable = await window.PublicKeyCredential.isConditionalMediationAvailable();
    if (!isConditionalMediationAvailable) {
      console.error('not isConditionalMediationAvailable');
      isPasskeySupported.value = false;
      return;
    }
  } catch (err) {
    console.error(err);
    isPasskeySupported.value = false;
    return;
  }
  isPasskeySupported.value = true;
});

// requests conditional mediation if passkeys are supported
const abortAuthentication = ref<AbortController | undefined>();
watch(
  isPasskeySupported,
  async (supported) => {
    if (!supported) {
      return;
    }
    abortAuthentication.value?.abort('re-requesting credential');
    abortAuthentication.value = undefined;
    try {
      const options = await getCredentialRequestOptions();
      console.log('credential request options:', options);
      abortAuthentication.value = new AbortController();
      const credential = await navigator.credentials.get({
        ...options,
        mediation: 'conditional',
        signal: abortAuthentication.value.signal,
      });
      abortAuthentication.value = undefined;
      console.log('assertion:', credential);
      const tokens = await authenticatePublicKeyCredential(
        credential as PublicKeyCredential,
      );
      console.log('authenticated:', tokens);
    } catch (err) {
      console.error(err);
    }
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  abortAuthentication.value?.abort('leaving page');
});

const username = ref('');

// obtains the public key credential request options
//
// throws if an error occurs.
const getCredentialRequestOptions = async (username?: string) => {
  let res;
  if (username != null) {
    // TODO: ask Cognito for sign-in of a specific user
    throw new Error("not implemented yet");
  } else {
    const endpoint =
      `${credentialsApiUrl.replace(/\/$/, '')}/discoverable/start`;
    res = await fetch(endpoint, {
      method: 'POST',
    });
  }
  return decodeCredentialRequestOptions(await res.json());
};

// decodes `CredentialRequestOptions`.
//
// converts "base64url"-encoded values into `Uint8Array`s.
const decodeCredentialRequestOptions = (options: any) => {
  return {
    publicKey: decodePublicKeyCredentialRequestOptions(options.publicKey),
  };
};

// decodes `PublicKeyCredentialRequestOptions`.
//
// converts "base64url"-encoded values into `Uint8Array`s.
const decodePublicKeyCredentialRequestOptions = (publicKey: any) => {
  return {
    ...publicKey,
    challenge: Base64.toUint8Array(publicKey.challenge),
    ...(
      publicKey.allowCredentials
        ? {
          allowCredentials: publicKey
            .allowCredentials
            .map(decodePublicKeyCredentialDescriptor)
        }
        : {}
    ),
  } as PublicKeyCredentialRequestOptions;
}

// decodes `PublicKeyCredentialDescriptor`.
//
// converts "base64url"-encoded `id` into `Uint8Array`.
const decodePublicKeyCredentialDescriptor = (descriptor: any) => {
  return {
    ...descriptor,
    id: Base64.toUint8Array(descriptor.id),
  } as PublicKeyCredentialDescriptor;
};

// authenticates a given public key credential.
const authenticatePublicKeyCredential = async (credential: PublicKeyCredential) => {
  const encodedCredential = encodePublicKeyCredential(credential);
  console.log('encoded credential:', encodedCredential);
  const userHandle = encodedCredential.response.userHandle;
  if (userHandle == null) {
    throw new Error("authenticator must return userHandle");
  }
  const challenge = await cognitoClient.send(new InitiateAuthCommand({
    ClientId: userPoolClientId,
    AuthFlow: 'CUSTOM_AUTH',
    AuthParameters: {
      USERNAME: userHandle,
    }
  }));
  if (challenge.ChallengeName !== 'CUSTOM_CHALLENGE') {
    throw new Error(`unexpected challenge name: ${challenge.ChallengeName}`);
  }
  // ignores challenge parameters for discoverable credentials
  const res = await cognitoClient.send(new RespondToAuthChallengeCommand({
    ClientId: userPoolClientId,
    ChallengeName: 'CUSTOM_CHALLENGE',
    Session: challenge.Session,
    ChallengeResponses: {
      USERNAME: userHandle,
      ANSWER: JSON.stringify(encodedCredential),
    },
  }));
  if (res.AuthenticationResult == null) {
    throw new Error('failed to authenticate');
  }
  return res.AuthenticationResult;
};

// encodes `PublicKeyCredential` for an API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
const encodePublicKeyCredential = (publicKey: PublicKeyCredential) => {
  return {
    id: publicKey.id,
    type: publicKey.type,
    rawId: Base64.fromUint8Array(new Uint8Array(publicKey.rawId), true),
    response: encodeAuthenticatorAssertionResponse(
      publicKey.response as AuthenticatorAssertionResponse,
    ),
    extensions: publicKey.getClientExtensionResults(),
  };
};

// encodes `AuthenticatorAssertionResponse` for an API request body.
//
// "base64url"-encodes:
// - `clientDataJSON`
// - `authenticatorData`
// - `signature`
// - `userHandle`
const encodeAuthenticatorAssertionResponse = (
  response: AuthenticatorAssertionResponse,
) => {
  return {
    clientDataJSON: Base64.fromUint8Array(
      new Uint8Array(response.clientDataJSON),
      true,
    ),
    authenticatorData: Base64.fromUint8Array(
      new Uint8Array(response.authenticatorData),
      true,
    ),
    signature: Base64.fromUint8Array(new Uint8Array(response.signature), true),
    ...(
      response.userHandle != null
        ? {
          userHandle: Base64.fromUint8Array(
            new Uint8Array(response.userHandle),
            true,
          ),
        }
        : {}
    ),
  };
};

// authenticates the user.
// references:
// - https://web.dev/articles/passkey-form-autofill
// - https://www.w3.org/TR/webauthn-3/
// const abortAuthentication = ref<AbortController | undefined>();
const onSubmit = async () => {
  console.log('manual authentication');
  abortAuthentication.value?.abort();
  abortAuthentication.value = undefined;
  const challenge = await cognitoClient.send(new InitiateAuthCommand({
    ClientId: userPoolClientId,
    AuthFlow: 'CUSTOM_AUTH',
    AuthParameters: {
      USERNAME: username.value,
    }
  }));
  console.log('challenge:', challenge);
  if (challenge.ChallengeName !== 'CUSTOM_CHALLENGE') {
    throw new Error(`unexpected challenge name: ${challenge.ChallengeName}`);
  }
  const userHandle = challenge.ChallengeParameters?.USERNAME;
  if (userHandle == null) {
    throw new Error('no USERNAME in challenge parameters');
  }
  const authOptionsJson = challenge.ChallengeParameters?.passkeyTestChallenge;
  if (authOptionsJson == null) {
    throw new Error('no passkeyTestChallenge in challenge parameters');
  }
  const authOptions =
    decodeCredentialRequestOptions(JSON.parse(authOptionsJson));
  console.log('authentication options', authOptions);
  const credential = await navigator.credentials.get(authOptions);
  if (credential == null) {
    throw new Error('failed to get public key credential');
  }
  const encodedCredential =
    encodePublicKeyCredential(credential as PublicKeyCredential);
  console.log('encoded credential:', encodedCredential);
  const res = await cognitoClient.send(new RespondToAuthChallengeCommand({
    ClientId: userPoolClientId,
    ChallengeName: 'CUSTOM_CHALLENGE',
    Session: challenge.Session,
    ChallengeResponses: {
      USERNAME: userHandle,
      ANSWER: JSON.stringify(encodedCredential),
    },
  }));
  if (res.AuthenticationResult == null) {
    throw new Error('failed to authenticate');
  }
  console.log('tokens', res.AuthenticationResult);
};
</script>

<template>
  <main>
    <form v-if="isPasskeySupported" @submit.prevent="onSubmit">
      <label>
        Username:
        <input
          name="username"
          v-model="username"
          autocomplete="username webauthn"
        >
      </label>
      <input type="submit" value="Sign In">
    </form>
    <p v-else-if="isPasskeySupported === undefined">
      Checking if passkeys are supported on this device...
    </p>
    <p v-else>
      Passkeys are not supported on this device.
    </p>
  </main>
</template>
