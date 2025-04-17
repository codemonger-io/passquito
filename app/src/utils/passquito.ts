import { parseCreationOptionsFromJSON } from '@github/webauthn-json/browser-ponyfill';
import {
  bufferToBase64url,
  convert,
  getRequestFromJSON,
  schema,
  type PublicKeyCredentialWithAssertionJSON,
  type PublicKeyCredentialWithAttestationJSON,
} from '@github/webauthn-json/extended';

import { credentialsApiUrl, isCognito } from '../auth-config';
import type { CredentialsApi } from './credentials-api';
import type { CognitoTokens, UserInfo, VerifiedUserInfo } from './passquito-types';
export type { CognitoTokens } from './passquito-types';

// passkey registration session.
interface RegistrationSession {
  sessionId: string;
  options: CredentialCreationOptions;
}

/** Raw Cognito tokens. */
export type RawCognitoTokens = Omit<CognitoTokens, 'activatedAt'>;

/**
 * Information about a public key.
 *
 * @beta
 */
export interface PublicKeyInfo {
  id: string;
  userHandle?: string | null;
  authenticatorAttachment?: string | null;
}

/**
 * Cognito tokens and the key info.
 *
 * @beta
 */
export interface Credentials {
  publicKeyInfo: PublicKeyInfo;
  tokens: CognitoTokens;
}

// global Credentials API object.
const credentialsApi: CredentialsApi = {
  async startRegistration(userInfo: UserInfo) {
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
      sessionId: session.sessionId,
      credentialCreationOptions: parseCreationOptionsFromJSON(session.credentialCreationOptions),
    };
  },
  async startRegistrationForVerifiedUser(userInfo: VerifiedUserInfo) {
    const endpoint = `${credentialsApiUrl.replace(/\/$/, '')}/registration/start-verified`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': userInfo.idToken,
      },
      body: JSON.stringify(userInfo.userInfo),
    });
    return await res.json();
  },
  async finishRegistration(sessionId: string, credential: PublicKeyCredential) {
    const endpoint = `${credentialsApiUrl.replace(/\/$/, '')}/registration/finish`;
    const encodedCredential = encodePublicKeyCredentialForCreation(credential);
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
  },
  async getDiscoverableCredentialRequestOptions() {
    const endpoint =
      `${credentialsApiUrl.replace(/\/$/, '')}/authentication/discover`;
    const res = await fetch(endpoint, {
      method: 'POST',
    });
    return getRequestFromJSON(await res.json());
  },
  async startAuthentication(userId: string) {
    const res = await fetch(`${credentialsApiUrl.replace(/\/$/, '')}/authentication/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ userId }),
    });
    const session = await res.json();
    return {
      sessionId: session.sessionId,
      credentialRequestOptions: getRequestFromJSON(session.credentialRequestOptions),
    };
  },
  async finishAuthentication(sessionId: string, userId: string, credential: PublicKeyCredential) {
    const encodedCredential = encodePublicKeyCredentialForAuthentication(credential);
    const res = await fetch(`${credentialsApiUrl.replace(/\/$/, '')}/authentication/finish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sessionId,
        userId,
        publicKey: encodedCredential,
      }),
    });
    const tokens = await res.json();
    if (!isRawCognitoTokens(tokens)) {
      throw new Error('invalid Cognito tokens');
    }
    return activateCognitoTokens(tokens);
  },
  async refreshTokens(refreshToken: string) {
    const endpoint = `${credentialsApiUrl.replace(/\/$/, '')}/authentication/refresh`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });
    // TODO: handle errors
    const tokens = await res.json();
    if (!isRawCognitoTokens(tokens)) {
      return undefined;
    }
    return activateCognitoTokens(tokens);
  },
};

/**
 * Checks if passkey registration is supported on the current device.
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
 * Checks if passkey authentication is supported on the current device.
 *
 * @remarks
 *
 * References:
 * - <https://web.dev/articles/passkey-form-autofill>
 * - <https://www.w3.org/TR/webauthn-3/>
 *
 * @beta
 */
export async function checkPasskeyAuthenticationSupported(): Promise<boolean> {
  if (!window.PublicKeyCredential) {
    console.error('no PublicKeyCredential');
    return false;
  }
  if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
    console.error('no PublicKeyCredential.isConditionalMediationAvailable');
    return false;
  }
  try {
    const isConditionalMediationAvailable = await window.PublicKeyCredential.isConditionalMediationAvailable();
    if (!isConditionalMediationAvailable) {
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

/**
 * Conducts a registration ceremony for a verified user.
 *
 * @remarks
 *
 * This ceremony is for a user who has been authenticated through a cross-device
 * authentication and wants to register a new device (credential).
 *
 * References:
 * - <https://web.dev/articles/passkey-registration>
 * - <https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential>
 *
 * @beta
 */
export async function doRegistrationCeremonyForVerifiedUser(userInfo: VerifiedUserInfo) {
  const { sessionId, options } = await startRegistrationForVerifiedUser(userInfo);
  console.log('CredentialCreationOptions:', options);
  const credential = await navigator.credentials.create(options);
  if (credential == null) {
    throw new Error('failed to create a new credential');
  }
  console.log('registering new credential:', credential);
  await registerPublicKeyCredential(sessionId, credential as PublicKeyCredential);
}

/**
 * Conducts an authentication ceremony.
 *
 * @remarks
 *
 * Reference:
 * - <https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion>
 *
 * @beta
 */
export function doAuthenticationCeremony() {
  let abortController: AbortController | undefined = new AbortController();
  const credentials = doAbortableAuthenticationCeremony(abortController).finally(() => {
    abortController = undefined;
  });
  return {
    abort: () => {
      if (abortController != null) {
        abortController.abort();
        abortController = undefined;
      }
    },
    credentials,
  };
}

/**
 * Conducts an authentication ceremony for a given user.
 *
 * @beta
 */
export function doAuthenticationCeremonyForUser(userId: string) {
  let abortController: AbortController | undefined = new AbortController();
  const credentials = doAbortableAuthenticationCeremonyForUser(userId, abortController).finally(() => {
    abortController = undefined;
  });
  return {
    abort: () => {
      if (abortController != null) {
        abortController.abort();
        abortController = undefined;
      }
    },
    credentials,
  };
}

// obtains the public key credential creation options
//
// throws if an error occurs.
async function startRegistration(userInfo: UserInfo): Promise<RegistrationSession> {
  const session = await credentialsApi.startRegistration(userInfo);
  return {
    sessionId: session.sessionId,
    options: session.credentialCreationOptions,
  };
}

// obtains the public key credential creation options for a verified user
//
// throws if an error occurs.
async function startRegistrationForVerifiedUser(userInfo: VerifiedUserInfo): Promise<RegistrationSession> {
  const session = await credentialsApi.startRegistrationForVerifiedUser(userInfo);
  return {
    sessionId: session.sessionId,
    options: session.credentialCreationOptions,
  };
}

// registers a public key credential.
//
// throws if an error occurs.
async function registerPublicKeyCredential(
  sessionId: string,
  credential: PublicKeyCredential,
) {
  await credentialsApi.finishRegistration(sessionId, credential);
}

// conducts an authentication ceremony with a give AbortController.
async function doAbortableAuthenticationCeremony(abortController: AbortController) {
  const options = await getCredentialRequestOptions();
  console.log('credential request options:', options);
  const credential = await navigator.credentials.get({
    ...options,
    mediation: 'conditional',
    signal: abortController.signal,
  });
  console.log('assertion:', credential);
  return await authenticateDiscoverablePublicKeyCredential(
    credential as PublicKeyCredential,
  );
}

// conducts an authentication ceremony for a given user with a given AbortController.
async function doAbortableAuthenticationCeremonyForUser(userId: string, abortController: AbortController) {
  const session = await startAuthenticationSessionForUser(userId);
  const { credentialRequestOptions } = session;
  console.log('credential request options:', credentialRequestOptions);
  const credential = await navigator.credentials.get({
    ...credentialRequestOptions,
    mediation: 'conditional',
    signal: abortController.signal,
  });
  console.log('assertion:', credential);
  return await finishAuthenticationSession(session, credential as PublicKeyCredential);
}

// obtains the public key credential request options
//
// throws if an error occurs.
async function getCredentialRequestOptions(username?: string) {
  // let res;
  if (username != null) {
    // TODO: ask Cognito for sign-in of a specific user
    throw new Error("not implemented yet");
  } else {
    return await credentialsApi.getDiscoverableCredentialRequestOptions();
  }
}

// authenticates a given public key credential in a discoverable manner.
async function authenticateDiscoverablePublicKeyCredential(credential: PublicKeyCredential): Promise<Credentials> {
  const encodedCredential = encodePublicKeyCredentialForAuthentication(credential);
  console.log('encoded credential:', encodedCredential);
  const publicKeyInfo = extractPublicKeyInfo(encodedCredential);
  if (isCognito) {
    const userHandle = encodedCredential.response.userHandle;
    if (userHandle == null) {
      throw new Error("authenticator must return userHandle");
    }
    const session = await credentialsApi.startAuthentication(userHandle);
    console.log('initiated authentication session:', session);
    // ignores challenge parameters for discoverable credentials
    const tokens = await credentialsApi.finishAuthentication(session.sessionId, userHandle, credential);
    return {
      publicKeyInfo,
      tokens,
    };
  } else {
    const endpoint =
      `${credentialsApiUrl.replace(/\/$/, '')}/discoverable/finish`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(encodedCredential),
    });
    return {
      publicKeyInfo,
      tokens: await res.json(),
    };
  }
}

// starts an authentication session.
async function startAuthenticationSessionForUser(userId: string) {
  return await credentialsApi.startAuthentication(userId);
}

// authenticates a given public key credential.
async function finishAuthenticationSession(
  session: any,
  credential: PublicKeyCredential,
): Promise<Credentials> {
  const encodedCredential = encodePublicKeyCredentialForAuthentication(credential);
  console.log('encoded credential:', encodedCredential);
  const userId = encodedCredential.response.userHandle;
  if (userId == null) {
    throw new Error("authenticator must return userHandle");
  }
  const publicKeyInfo = extractPublicKeyInfo(encodedCredential);
  const tokens = await credentialsApi.finishAuthentication(session.sessionId, userId, credential);
  return {
    publicKeyInfo,
    tokens,
  };
}

// encodes `PublicKeyCredential` for a registration API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
function encodePublicKeyCredentialForCreation(publicKey: PublicKeyCredential): PublicKeyCredentialWithAttestationJSON {
  return convert(
    bufferToBase64url,
    schema.publicKeyCredentialWithAttestation,
    publicKey,
  );
}

// encodes `PublicKeyCredential` for an authentication API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
function encodePublicKeyCredentialForAuthentication(publicKey: PublicKeyCredential): PublicKeyCredentialWithAssertionJSON {
  return convert(
    bufferToBase64url,
    schema.publicKeyCredentialWithAssertion,
    publicKey,
  );
}

// Extracts public key information from an encoded public key credential.
function extractPublicKeyInfo(publicKey: PublicKeyCredentialWithAssertionJSON): PublicKeyInfo {
  return {
    id: publicKey.id,
    userHandle: publicKey.response.userHandle,
    authenticatorAttachment: publicKey.authenticatorAttachment,
  };
}

/**
 * Refreshes ID and access tokens with a given refresh token.
 *
 * @beta
 */
export async function refreshTokens(refreshToken: string): Promise<CognitoTokens | undefined> {
  return await credentialsApi.refreshTokens(refreshToken);
}

/**
 * Returns if a given value is a `PublicKeyInfo`.
 *
 * @beta
 */
export function isPublicKeyInfo(value: unknown): value is PublicKeyInfo {
  if (value == null || typeof value !== 'object') {
    return false;
  }
  const maybeKeyInfo = value as PublicKeyInfo;
  if (typeof maybeKeyInfo.id !== 'string') {
    return false;
  }
  if (maybeKeyInfo.userHandle != null && typeof maybeKeyInfo.userHandle !== 'string') {
    return false;
  }
  if (maybeKeyInfo.authenticatorAttachment != null && typeof maybeKeyInfo.authenticatorAttachment !== 'string') {
    return false;
  }
  return true;
}

/**
 * Returns if a given value is a `RawCognitoTokens`.
 *
 * @beta
 */
export function isRawCognitoTokens(value: unknown): value is RawCognitoTokens {
  if (value == null || typeof value !== 'object') {
    return false;
  }
  const maybeTokens = value as RawCognitoTokens;
  return typeof maybeTokens.idToken === 'string' &&
    typeof maybeTokens.accessToken === 'string' &&
    typeof maybeTokens.refreshToken === 'string' &&
    typeof maybeTokens.expiresIn === 'number';
}

/**
 * Returns if a given value is a `CognitoTokens`.
 *
 * @beta
 */
export function isCognitoTokens(value: unknown): value is CognitoTokens {
  if (!isRawCognitoTokens(value)) {
    return false;
  }
  const maybeTokens = value as CognitoTokens;
  return typeof maybeTokens.activatedAt === 'number';
}

/**
 * Activates a given `RawCognitoTokens` and obtains a `CognitoTokens`.
 *
 * @remarks
 *
 * You should call this function as soon as you obtain Cognito tokens.
 *
 * @beta
 */
export function activateCognitoTokens(tokens: RawCognitoTokens): CognitoTokens {
  return {
    ...tokens,
    activatedAt: Date.now(),
  };
}

/**
 * Returns if a given error object is an `AbortError`.
 *
 * @beta
 */
export function isAbortError(err: unknown): boolean {
  if (err == null || (typeof err !== 'object' && typeof err !== 'function')) {
    return false;
  }
  return (err as { name: string }).name === 'AbortError';
}

/**
 * Returns the name of a given error object.
 *
 * @beta
 */
export function getErrorName(err: unknown): string | undefined {
  if (err == null || (typeof err !== 'object' && typeof err !== 'function')) {
    return undefined;
  }
  return (err as { name: string }).name;
}
