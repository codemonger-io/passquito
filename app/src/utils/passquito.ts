import { Base64 } from 'js-base64';

import { credentialsApiUrl, isCognito, userPoolClientId } from '../auth-config';

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

/**
 * User information for invited registration.
 *
 * @beta
 */
export interface VerifiedUserInfo {
  /** ID token of the verified user. */
  idToken: string;

  /** User information. */
  userInfo: UserInfo;
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
 * Raw cognito tokens.
 *
 * @beta
 */
export interface RawCognitoTokens {
  idToken: string;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * Cognito tokens with an appointed expiration time.
 *
 * @beta
 */
export type CognitoTokens = RawCognitoTokens & {
  /**
   * Activation time represented as the number of milliseconds elapsed since
   * 00:00:00 on January 1, 1970 in UTC.
   *
   * @remarks
   *
   * Expiration time of tokens is approximately this value plus `expiresIn` x
   * 1000.
   */
  activatedAt: number,
};

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

// obtains the public key credential creation options for a verified user
//
// throws if an error occurs.
async function startRegistrationForVerifiedUser(userInfo: VerifiedUserInfo): Promise<RegistrationSession> {
  const endpoint = `${credentialsApiUrl.replace(/\/$/, '')}/registration/start-verified`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': userInfo.idToken,
    },
    body: JSON.stringify(userInfo.userInfo),
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

// decodes `PublicKeyCredentialDescriptor`.
//
// converts "base64url"-encoded `id` into `Uint8Array`.
function decodePublicKeyCredentialDescriptor(descriptor: any) {
  return {
    ...descriptor,
    id: Base64.toUint8Array(descriptor.id),
  } as PublicKeyCredentialDescriptor;
}

// encodes `PublicKeyCrendential` for a registration API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
function encodePublicKeyCredentialForCreation(publicKey: PublicKeyCredential) {
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
  return await authenticatePublicKeyCredential(
    credential as PublicKeyCredential,
  );
}

// obtains the public key credential request options
//
// throws if an error occurs.
async function getCredentialRequestOptions(username?: string) {
  let res;
  if (username != null) {
    // TODO: ask Cognito for sign-in of a specific user
    throw new Error("not implemented yet");
  } else {
    const endpoint =
      `${credentialsApiUrl.replace(/\/$/, '')}/authentication/discover`;
    res = await fetch(endpoint, {
      method: 'POST',
    });
  }
  return decodeCredentialRequestOptions(await res.json());
}

// decodes `CredentialRequestOptions`.
//
// converts "base64url"-encoded values into `Uint8Array`s.
function decodeCredentialRequestOptions(options: any) {
  return {
    publicKey: decodePublicKeyCredentialRequestOptions(options.publicKey),
  };
}

// decodes `PublicKeyCredentialRequestOptions`.
//
// converts "base64url"-encoded values into `Uint8Array`s.
function decodePublicKeyCredentialRequestOptions(publicKey: any) {
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

// authenticates a given public key credential.
async function authenticatePublicKeyCredential(credential: PublicKeyCredential): Promise<Credentials> {
  const encodedCredential = encodePublicKeyCredentialForAuthentication(credential);
  console.log('encoded credential:', encodedCredential);
  const publicKeyInfo = extractPublicKeyInfo(encodedCredential);
  if (isCognito) {
    const userHandle = encodedCredential.response.userHandle;
    if (userHandle == null) {
      throw new Error("authenticator must return userHandle");
    }
    const startRes = await fetch(`${credentialsApiUrl.replace(/\/$/, '')}/authentication/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ userId: userHandle }),
    });
    const session = await startRes.json();
    console.log('initiated authentication session:', session);
    // ignores challenge parameters for discoverable credentials
    const finishRes = await fetch(`${credentialsApiUrl.replace(/\/$/, '')}/authentication/finish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sessionId: session.sessionId,
        userId: userHandle,
        publicKey: encodedCredential,
      }),
    });
    const tokens = await finishRes.json();
    if (!isRawCognitoTokens(tokens)) {
      throw new Error('invalid Cognito tokens');
    }
    return {
      publicKeyInfo,
      tokens: activateCognitoTokens(tokens),
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

// encodes `PublicKeyCredential` for an authentication API request body.
//
// "base64url"-encodes `ArrayBuffer`s.
function encodePublicKeyCredentialForAuthentication(publicKey: PublicKeyCredential) {
  return {
    id: publicKey.id,
    type: publicKey.type,
    rawId: Base64.fromUint8Array(new Uint8Array(publicKey.rawId), true),
    response: encodeAuthenticatorAssertionResponse(
      publicKey.response as AuthenticatorAssertionResponse,
    ),
    authenticatorAttachment: publicKey.authenticatorAttachment,
    extensions: publicKey.getClientExtensionResults(),
  };
}

// encodes `AuthenticatorAssertionResponse` for an API request body.
//
// "base64url"-encodes:
// - `clientDataJSON`
// - `authenticatorData`
// - `signature`
// - `userHandle`
function encodeAuthenticatorAssertionResponse(
  response: AuthenticatorAssertionResponse,
) {
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
}

type EncodedPublicKeyCredential = ReturnType<typeof encodePublicKeyCredentialForAuthentication>;

// Extracts public key information from an encoded public key credential.
function extractPublicKeyInfo(publicKey: EncodedPublicKeyCredential): PublicKeyInfo {
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
