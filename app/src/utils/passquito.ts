import { Base64 } from 'js-base64';

import { credentialsApiUrl } from '../auth-config';

/**
 * User information for registration.
 *
 * @beta
 */
export interface UserInfo {
  /** Username. */
  username: string;

  /** Display name. */
  displayName: string;
}

// passkey registration session.
interface RegistrationSession {
  sessionId: string;
  options: CredentialCreationOptions;
}

// options given to `navigator.credentials.create()`.
//
// we are not interested in the fields other than `publicKey`.
interface CredentialCreationOptions {
  publicKey: PublicKeyCredentialCreationOptions;
}

/**
 * Checks if passkey registration is supported in the current context.
 *
 * @remarks
 *
 * References:
 * - <https://web.dev/articles/passkey-registration>
 * - <https://www.w3.org/TR/webauthn-3/>
 *
 * @beta
 */
export async function checkPasskeyRegistrationSupported(): Promise<boolean> {
  if (!window.PublicKeyCredential) {
    console.error('no PublicKeyCredential');
    return false;
  }
  if (typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
    console.error('no isUserVerifyingPlatformAuthenticatorAvailable function');
    return false;
  }
  if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
    console.error('no isConditionalMediationAvailable function');
    return false;
  }
  const isUserVerifyingPlatformAuthenticatorAvailable =
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  const isConditionalMediationAvailable =
    window.PublicKeyCredential.isConditionalMediationAvailable();
  try {
    if (!await isUserVerifyingPlatformAuthenticatorAvailable) {
      console.error('not isUserVerifyingPlatformAuthenticatorAvailable');
      return false;
    }
    if (!await isConditionalMediationAvailable) {
      console.error('not isConditionalMediationAvailable');
      return false;
    }
  } catch (err) {
    console.error(err);
    return false;
  }
  return true;
}

/**
 * Conducts a registration ceremony.
 *
 * @remarks
 *
 * References:
 * - <https://web.dev/articles/passkey-registration>
 * - <https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential>
 *
 * @beta
 */
export async function doRegistrationCeremony(userInfo: UserInfo) {
    const { sessionId, options } = await startRegistration(userInfo);
    console.log('CredentialCreationOptions:', options);
    const credential = await navigator.credentials.create(options);
    if (credential == null) {
      throw new Error('failed to create a new credential');
    }
    console.log('registering new credential:', credential);
    await registerPublicKeyCredential(sessionId, credential as PublicKeyCredential);
}

// obtains the public key credential creation options
//
// throws if an error occurs.
async function startRegistration(userInfo: UserInfo): Promise<RegistrationSession> {
  const endpoint = `${credentialsApiUrl.replace(/\/$/, '')}/registration/start`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userInfo),
  });
  const session = await res.json();
  return {
    sessionId: session.sessionId as string,
    options: decodeCredentialCreationOptions(session.credentialCreationOptions),
  };
}

// registers a public key credential.
//
// throws if an error occurs.
async function registerPublicKeyCredential(
  sessionId: string,
  credential: PublicKeyCredential,
) {
  const endpoint = `${credentialsApiUrl.replace(/\/$/, '')}/registration/finish`;
  const encodedCredential = encodePublicKeyCredential(credential);
  console.log('encoded credential:', encodedCredential);
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      sessionId,
      publicKeyCredential: encodedCredential,
    }),
  });
  if (!res.ok) {
    throw new Error(
      `credential registration failed with ${res.status}: ${await res.text()}`,
    );
  }
}

// decodes `CredentialCreationOptions` in a registration start API response.
//
// converts "base64url"-encoded values into `Uint8Array`s.
function decodeCredentialCreationOptions(options: any): CredentialCreationOptions {
  return {
    publicKey: decodePublicKeyCredentialCreationOptions(options.publicKey),
  };
}

// decodes `PublicKeyCredentialCreationOptions` in a registration start API
// response.
//
// converts "base64url"-encoded values into `Uint8Array`s.
function decodePublicKeyCredentialCreationOptions(publicKey: any) {
  return {
    ...publicKey,
    user: decodePublicKeyCredentialUserEntity(publicKey.user),
    challenge: Base64.toUint8Array(publicKey.challenge),
    ...(
      publicKey.excludeCredentials
        ? {
            excludeCredentials: publicKey.excludeCredentials.map(
              decodePublicKeyCredentialDescriptor,
            )
          }
        : {}
    ),
  } as PublicKeyCredentialCreationOptions;
}

// decodes `PublicKeyCredentialUserEntity` in a registration start API response.
//
// converts "base64url"-encoded `id` into `Uint8Array`.
function decodePublicKeyCredentialUserEntity(user: any) {
  return {
    ...user,
    id: Base64.toUint8Array(user.id),
  } as PublicKeyCredentialUserEntity;
}

// decodes `PublicKeyCredentialDescriptor` in a registration start API response.
//
// converts "base64url"-encoded `id` into `Uint8Array`.
function decodePublicKeyCredentialDescriptor(descriptor: any) {
  return {
    ...descriptor,
    id: Base64.toUint8Array(descriptor.id),
  } as PublicKeyCredentialDescriptor;
}

// encodes `PublicKeyCrendential` for a registration finish API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
function encodePublicKeyCredential(publicKey: PublicKeyCredential) {
  return {
    id: publicKey.id,
    type: publicKey.type,
    rawId: Base64.fromUint8Array(new Uint8Array(publicKey.rawId), true),
    response: encodeAuthenticatorAttestationResponse(
      publicKey.response as AuthenticatorAttestationResponse,
    ),
    extensions: publicKey.getClientExtensionResults(),
  };
}

// encodes `AuthenticatorAttestationResponse` for a registration finish API
// request body.
//
// "base64url"-encodes `clientDataJSON`, and `attestationObject`.
function encodeAuthenticatorAttestationResponse(
  response: AuthenticatorAttestationResponse,
) {
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
}
