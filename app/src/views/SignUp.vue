<script setup lang="ts">
import { Base64 } from 'js-base64';
import { onMounted, ref } from 'vue';

const authBaseUrl = 'http://localhost:3000/auth';

// checks if passkeys are supported 
// references:
// - https://web.dev/articles/passkey-registration
// - https://www.w3.org/TR/webauthn-3/
const isPasskeySupported = ref(false);
onMounted(async () => {
  if (!window.PublicKeyCredential) {
    console.error('no PublicKeyCredential');
    return;
  }
  if (typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
    console.error('no isUserVerifyingPlatformAuthenticatorAvailable function');
    return;
  }
  if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
    console.error('no isConditionalMediationAvailable function');
    return;
  }
  const isUserVerifyingPlatformAuthenticatorAvailable = window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  const isConditionalMediationAvailable = window.PublicKeyCredential.isConditionalMediationAvailable();
  try {
    if (!await isUserVerifyingPlatformAuthenticatorAvailable) {
      console.error('not isUserVerifyingPlatformAuthenticatorAvailable');
      return;
    }
    if (!await isConditionalMediationAvailable) {
      console.error('not isConditionalMediationAvailable');
      return;
    }
  } catch (err) {
    console.error(err);
    return;
  }
  isPasskeySupported.value = true;
});

const username = ref('');
const displayName = ref('');

// obtains the public key credential creation options
//
// throws if an error occurs.
const getCredentialCreationOptions = async (
  userInfo: { username: string, displayName: string },
) => {
  const endpoint = `${authBaseUrl}/register-start`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userInfo),
  });
  return decodeCredentialCreationOptions(await res.json());
};

// registers a public key credential.
//
// throw if an error occurs.
const registerPublicKeyCredential = async (credential: PublicKeyCredential) => {
  const endpoint = `${authBaseUrl}/register-finish`;
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
      `credential registration failed with ${res.status}: ${await res.text()}`,
    );
  }
};

// decodes `CredentialCreationOptions` in an API response.
//
// converts "base64url"-encoded values into `Uint8Array`s.
const decodeCredentialCreationOptions = (options: any) => {
  return {
    publicKey: decodePublicKeyCredentialCreationOptions(options.publicKey),
  };
};

// decodes `PublicKeyCredentialCreationOptions` in an API response.
//
// converts "base64url"-encoded values into `Uint8Array`s.
const decodePublicKeyCredentialCreationOptions = (publicKey: any) => {
  return {
    ...publicKey,
    user: decodePublicKeyCredentialUserEntity(publicKey.user),
    challenge: Base64.toUint8Array(publicKey.challenge),
    ...(publicKey.excludeCredentials?.map(decodePublicKeyCredentialDescriptor) || {}),
  } as PublicKeyCredentialCreationOptions;
};

// decodes `PublicKeyCredentialUserEntity` in an API response.
//
// converts "base64url"-encoded `id` into `Uint8Array`.
const decodePublicKeyCredentialUserEntity = (user: any) => {
  return {
    ...user,
    id: Base64.toUint8Array(user.id),
  } as PublicKeyCredentialUserEntity;
};

// decodes `PublicKeyCredentialDescriptor` in an API response.
//
// converts "base64url"-encoded `id` into `Uint8Array`.
const decodePublicKeyCredentialDescriptor = (descriptor: any) => {
  return {
    ...descriptor,
    id: Base64.toUint8Array(descriptor.id),
  } as PublicKeyCredentialDescriptor;
};

// encodes `PublicKeyCrendential` for an API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
const encodePublicKeyCredential = (publicKey: PublicKeyCredential) => {
  return {
    id: publicKey.id,
    type: publicKey.type,
    rawId: Base64.fromUint8Array(new Uint8Array(publicKey.rawId), true),
    response: encodeAuthenticatorAttestationResponse(
      publicKey.response as AuthenticatorAttestationResponse,
    ),
    extensions: publicKey.getClientExtensionResults(),
  };
};

// encodes `AuthenticatorAttestationResponse` for an API request body.
//
// "base64url"-encodes `clientDataJSON`, and `attestationObject`.
const encodeAuthenticatorAttestationResponse = (
  response: AuthenticatorAttestationResponse,
) => {
  return {
    clientDataJSON: Base64.fromUint8Array(
      new Uint8Array(response.clientDataJSON),
      true,
    ),
    attestationObject: Base64.fromUint8Array(
      new Uint8Array(response.attestationObject),
      true,
    ),
    transports: response.getTransports(),
  };
};

// creates a new passkey
// references:
// - https://web.dev/articles/passkey-registration
// - https://www.w3.org/TR/webauthn-3/
const onSubmit = async () => {
  try {
    const options = await getCredentialCreationOptions({
      username: username.value,
      displayName: displayName.value,
    });
    console.log('CredentialCreationOptions:', options);
    const credential = await navigator.credentials.create(options);
    if (credential == null) {
      throw new Error('failed to create a new credential');
    }
    console.log('registering new credential:', credential);
    await registerPublicKeyCredential(credential as PublicKeyCredential);
    console.log('finished registration!');
  } catch(err) {
    console.error(err);
  }
};
</script>

<template>
  <main>
    <form v-if="isPasskeySupported" @submit.prevent="onSubmit">
      <label>
        Username:
        <input name="username" v-model="username" pattern="[A-Za-z0-9_-:;]+">
      </label>
      <label>
        Display name:
        <input name="display-name" v-model="displayName">
      </label>
      <input type="submit" value="Sign Up">
    </form>
    <p v-else>
      Passkeys are not supported on this device.
    </p>
  </main>
</template>
