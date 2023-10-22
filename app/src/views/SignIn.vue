<script setup lang="ts">
import { Base64 } from 'js-base64';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';

import { useWebauthn } from '../composables/webauthn';

const { baseUrl } = useWebauthn();

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
      const userInfo = await authenticatePublicKeyCredential(
        credential as PublicKeyCredential,
      );
      console.log('authenticated:', userInfo);
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
  const endpoint = `${baseUrl}login-start`;
  let res;
  if (username != null) {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username }),
    });
  } else {
    res = await fetch(endpoint);
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
  const endpoint = `${baseUrl}login-finish`;
  const encodedCredential = encodePublicKeyCredential(credential);
  console.log('encoded credential:', encodedCredential);
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(encodedCredential),
  });
  if (!res.ok) {
    throw new Error(
      `authentication failed with ${res.status}: ${await res.text()}`
    );
  }
  return await res.json();
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
  // TODO: support manual authentication
  /*
  try {
    const options = await getCredentialRequestOptions(username.value);
    console.log('credential request options:', options);
    abortAuthentication.value = new AbortController();
    const assertion = await navigator.credentials.get({
      ...options,
      mediation: 'conditional',
      signal: abortAuthentication.value.signal,
    });
    abortAuthentication.value = undefined;
    console.log('assertion:', assertion);
  } catch (err) {
    console.error(err);
  } */
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
