import { parseCreationOptionsFromJSON } from '@github/webauthn-json/browser-ponyfill';
import {
  bufferToBase64url,
  convert,
  getRequestFromJSON,
  schema,
  type PublicKeyCredentialWithAssertionJSON ,
  type PublicKeyCredentialWithAttestationJSON,
} from '@github/webauthn-json/extended';

import type { CredentialsApi } from './credentials-api';
import type {
  CognitoTokens,
  UserInfo,
  VerifiedUserInfo,
} from './passquito-types';

// raw Cognito tokens returned from the API
type RawCognitoTokens = Omit<CognitoTokens, 'activatedAt'>;

/**
 * Default implementation of {@link CredentialsApi}.
 *
 * @beta
 */
export class CredentialsApiImpl implements CredentialsApi {
  /** Base URL of the Credentials API. */
  readonly baseUrl: string;

  /** Initializes with a given base URL of the Credentials API. */
  constructor(baseUrl: string) {
    // removes a trailing slash if it exists
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async startRegistration(userInfo: UserInfo) {
    const endpoint = `${this.baseUrl}/registration/start`;
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
  }

  async startRegistrationForVerifiedUser(userInfo: VerifiedUserInfo) {
    const endpoint = `${this.baseUrl}/registration/start-verified`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': userInfo.idToken,
      },
      body: JSON.stringify(userInfo.userInfo),
    });
    return await res.json();
  }

  async finishRegistration(sessionId: string, credential: PublicKeyCredential) {
    const endpoint = `${this.baseUrl}/registration/finish`;
    const encodedCredential = encodePublicKeyCredentialForCreation(credential);
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

  async getDiscoverableCredentialRequestOptions() {
    const endpoint = `${this.baseUrl}/authentication/discover`;
    const res = await fetch(endpoint, {
      method: 'POST',
    });
    return getRequestFromJSON(await res.json());
  }

  async startAuthentication(userId: string) {
    const res = await fetch(`${this.baseUrl}/authentication/start`, {
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
  }

  async finishAuthentication(sessionId: string, userId: string, credential: PublicKeyCredential) {
    const encodedCredential = encodePublicKeyCredentialForAuthentication(credential);
    const res = await fetch(`${this.baseUrl}/authentication/finish`, {
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
  }

  async refreshTokens(refreshToken: string) {
    const endpoint = `${this.baseUrl}/authentication/refresh`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });
    const tokens = await res.json();
    if (!isRawCognitoTokens(tokens)) {
      return undefined;
    }
    return activateCognitoTokens(tokens);
  }
}

// encodes `PublicKeyCredential` for a registration API request body.
//
// replaces `ArrayBuffer`s with Base64-URL-encoded strings.
function encodePublicKeyCredentialForCreation(
  publicKey: PublicKeyCredential,
): PublicKeyCredentialWithAttestationJSON {
  return convert(
    bufferToBase64url,
    schema.publicKeyCredentialWithAttestation,
    publicKey,
  );
}

// encodes `PublicKeyCredential` for an authentication API request body.
//
// replaces `ArrayBuffer`s with Base64-URL-encoded strings.
function encodePublicKeyCredentialForAuthentication(
  publicKey: PublicKeyCredential,
): PublicKeyCredentialWithAssertionJSON {
  return convert(
    bufferToBase64url,
    schema.publicKeyCredentialWithAssertion,
    publicKey,
  );
}

// returns if a given value is a `RawCognitoTokens`.
function isRawCognitoTokens(value: unknown): value is RawCognitoTokens {
  if (value == null || typeof value !== 'object') {
    return false;
  }
  const maybeTokens = value as RawCognitoTokens;
  return typeof maybeTokens.idToken === 'string' &&
    typeof maybeTokens.accessToken === 'string' &&
    typeof maybeTokens.refreshToken === 'string' &&
    typeof maybeTokens.expiresIn === 'number';
}

// activates a given `RawCognitoTokens` and obtains a `CognitoTokens`.
//
// you should call this function as soon as you obtain Cognito tokens.
function activateCognitoTokens(tokens: RawCognitoTokens): CognitoTokens {
  return {
    ...tokens,
    activatedAt: Date.now(),
  };
}
