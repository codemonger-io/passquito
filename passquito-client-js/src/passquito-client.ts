import { bufferToBase64url } from '@github/webauthn-json/extended';

import type { ApiResponse, CredentialsApi, RegistrationSession } from './credentials-api';
import type {
  CognitoTokens,
  PublicKeyInfo,
  UserInfo,
  VerifiedUserInfo,
} from './types';

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
 * Cause of {@link PassquitoClientError}.
 *
 * @remarks
 *
 * You can tell the actual type of the cause by checking the `type` field.
 *
 * @beta
 */
export type PassquitoClientErrorCause =
  | PassquitoClientErrorCauseCredentialsApi
  | PassquitoClientErrorCauseGeneric;

/**
 * Error cause related to the Credentials API.
 *
 * @beta
 */
export interface PassquitoClientErrorCauseCredentialsApi {
  type: 'credentials-api';

  response: ApiResponse<unknown>;
}

/**
 * Wraps an {@link ApiResponse} with {@link PassquitoClientErrorCauseCredentialsApi}.
 *
 * @beta
 */
function makeCredentialsApiErrorCause(
  response: ApiResponse<unknown>,
): PassquitoClientErrorCauseCredentialsApi {
  return {
    type: 'credentials-api',
    response,
  }
}

/**
 * Generic error cause.
 *
 * @beta
 */
export interface PassquitoClientErrorCauseGeneric {
  type: 'generic';

  error: unknown;
}

/**
 * Wraps an `Error` with {@link PassquitoClientErrorCauseGeneric}.
 *
 * @beta
 */
function makeGenericErrorCause(error: unknown): PassquitoClientErrorCauseGeneric {
  return {
    type: 'generic',
    error,
  }
}

/**
 * Error thrown by {@link PassquitoClient}.
 *
 * @beta
 */
export class PassquitoClientError extends Error {
  /** Cause of the error. */
  readonly cause?: PassquitoClientErrorCause;

  constructor(message: string, cause?: PassquitoClientErrorCause) {
    super(message);
    this.name = 'PassquitoClientError';
    this.cause = cause;
  }
}

/**
 * Passquito client.
 *
 * @beta
 */
export class PassquitoClient {
  /**
   * Initializes with a given {@link CredentialsApi} instance.
   *
   * @param credentialsApi - Credentials API access.
   */
  constructor(private readonly credentialsApi: CredentialsApi) {}

  /**
   * Conducts a registration ceremony.
   *
   * @remarks
   *
   * References:
   * - https://web.dev/articles/passkey-registration
   * - https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
   *
   * @returns
   *
   *   Public key information of the newly registered user.
   *
   * @throws PassquitoClientError -
   *
   *   When the registration ceremony fails.
   */
  async doRegistrationCeremony(userInfo: UserInfo): Promise<PublicKeyInfo> {
    const startRes = await this.credentialsApi.startRegistration(userInfo);
    if (!startRes.ok) {
      throw new PassquitoClientError(
        'failed to start registration session',
        makeCredentialsApiErrorCause(startRes),
      );
    }
    try {
      return this.runRegistrationSession(await startRes.parse());
    } catch (err) {
      throw new PassquitoClientError(
        'invalid start registration response',
        makeGenericErrorCause(err),
      );
    }
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
   * - https://web.dev/articles/passkey-registration
   * - https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
   *
   * @returns
   *
   *   Public key information of the newly registered credential.
   *   The unique user ID shall be the same as `userInfo`.
   *
   * @throws PassquitoClientError -
   *
   *   When the registration ceremony fails.
   */
  async doRegistrationCeremonyForVerifiedUser(userInfo: VerifiedUserInfo): Promise<PublicKeyInfo> {
    const startRes = await this.credentialsApi.startRegistrationForVerifiedUser(userInfo);
    if (!startRes.ok) {
      throw new PassquitoClientError(
        'failed to start registration session for verified user',
        makeCredentialsApiErrorCause(startRes),
      );
    }
    try {
      return this.runRegistrationSession(await startRes.parse());
    } catch (err) {
      throw new PassquitoClientError(
        'invalid start registration response for verified user',
        makeGenericErrorCause(err),
      );
    }
  }

  // runs a given registration session.
  private async runRegistrationSession(session: RegistrationSession): Promise<PublicKeyInfo> {
    const credential = await navigator.credentials.create(
      session.credentialCreationOptions,
    ) as (PublicKeyCredential | null);
    if (credential == null) {
      throw new PassquitoClientError('failed to create a new credential');
    }
    const finishRes = await this.credentialsApi.finishRegistration(
      session.sessionId,
      credential,
    );
    if (!finishRes.ok) {
      throw new PassquitoClientError(
        'failed to finish registration',
        makeCredentialsApiErrorCause(finishRes),
      );
    }
    let userId;
    try {
      ({ userId } = await finishRes.parse());
    } catch (err) {
      throw new PassquitoClientError(
        'invalid finish registration response',
        makeGenericErrorCause(err),
      );
    }
    const publicKeyInfo = extractPublicKeyInfo(credential);
    // NOTE: no `userHandle` is available in an attestation (registration)
    // response, so we substitute it with the user ID obtained from the
    // Credentials API.
    publicKeyInfo.userHandle = userId;
    return publicKeyInfo;
  }

  /**
   * Conducts an authentication ceremony.
   *
   * @remarks
   *
   * While the authentication ceremony itself is conducted in an asynchronous
   * manner, this function synchronously returns a function to abort the
   * ceremony and a `Promise` of the credentials.
   *
   * The `Promise` of the credentials will throw {@link PassquitoClientError}
   * when the authentication ceremony fails.
   * It will throw `DOMException` with `name="AbortError"` when the ceremony is
   * aborted.
   *
   * Reference:
   * - https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
   */
  doAuthenticationCeremony() {
    return runAbortableAuthentication((abortController) => {
      return this.doAbortableAuthenticationCeremony(abortController);
    });
  }

  /**
   * Conducts an authentication ceremony for a given user.
   *
   * @remarks
   *
   * While the authentication ceremony itself is conducted in an asynchronous
   * manner, this function synchronously returns a function to abort the
   * ceremony and a `Promise` of the credentials.
   *
   * The `Promise` of the credentials will throw {@link PassquitoClientError}
   * when the authentication ceremony fails.
   * It will throw `DOMException` with `name="AbortError"` when the ceremony is
   * aborted.
   */
  doAuthenticationCeremonyForUser(userId: string) {
    return runAbortableAuthentication((abortController) => {
      return this.doAbortableAuthenticationCeremonyForUser(userId, abortController);
    });
  }

  // conducts an authentication ceremony with a given AbortController.
  private async doAbortableAuthenticationCeremony(
    abortController: AbortController,
  ) {
    const getOptionsRes = await this.credentialsApi.getDiscoverableCredentialRequestOptions();
    if (!getOptionsRes.ok) {
      throw new PassquitoClientError(
        'failed to get discoverable credential request options',
        makeCredentialsApiErrorCause(getOptionsRes),
      );
    }
    let options;
    try {
      options = await getOptionsRes.parse();
    } catch (err) {
      throw new PassquitoClientError(
        'invalid discoverable credential request options response',
        makeGenericErrorCause(err),
      );
    }
    const credential = await navigator.credentials.get({
      ...options,
      mediation: 'conditional',
      signal: abortController.signal,
    }) as (PublicKeyCredential | null);
    if (credential == null) {
      throw new PassquitoClientError('public key credential must be provided');
    }
    const publicKeyInfo = extractPublicKeyInfo(credential);
    const { userHandle } = publicKeyInfo;
    if (userHandle == null) {
      throw new PassquitoClientError('authenticator must return userHandle');
    }
    const startRes = await this.credentialsApi.startAuthentication(userHandle);
    if (!startRes.ok) {
      throw new PassquitoClientError(
        'failed to start authentication',
        makeCredentialsApiErrorCause(startRes),
      );
    }
    let sessionId;
    try {
      ({ sessionId } = await startRes.parse());
    } catch (err) {
      throw new PassquitoClientError(
        'invalid start authentication response',
        makeGenericErrorCause(err),
      );
    }
    // ignores other parameters for discoverable credentials
    const finishRes = await this.credentialsApi.finishAuthentication(
      sessionId,
      userHandle,
      credential,
    );
    if (!finishRes.ok) {
      throw new PassquitoClientError(
        'failed to finish authentication',
        makeCredentialsApiErrorCause(finishRes),
      );
    }
    let tokens;
    try {
      tokens = await finishRes.parse();
    } catch (err) {
      throw new PassquitoClientError(
        'invalid finish authentication response',
        makeGenericErrorCause(err),
      );
    }
    return {
      publicKeyInfo,
      tokens,
    };
  }

  // conducts an authentication ceremony for a given user with a given
  // AbortController.
  private async doAbortableAuthenticationCeremonyForUser(
    userId: string,
    abortController: AbortController,
  ) {
    const startRes = await this.credentialsApi.startAuthentication(userId);
    if (!startRes.ok) {
      throw new PassquitoClientError(
        'failed to start authentication',
        makeCredentialsApiErrorCause(startRes),
      );
    }
    let session;
    try {
      session = await startRes.parse();
    } catch (err) {
      throw new PassquitoClientError(
        'invalid start authentication response',
        makeGenericErrorCause(err),
      );
    }
    const credential = await navigator.credentials.get({
      ...session.credentialRequestOptions,
      mediation: 'conditional',
      signal: abortController.signal,
    }) as (PublicKeyCredential | null);
    if (credential == null) {
      throw new PassquitoClientError('public key credential must be provided');
    }
    const finishRes = await this.credentialsApi.finishAuthentication(
      session.sessionId,
      userId,
      credential,
    );
    if (!finishRes.ok) {
      throw new PassquitoClientError(
        'failed to finish authentication',
        makeCredentialsApiErrorCause(finishRes),
      );
    }
    let tokens;
    try {
      tokens = await finishRes.parse();
    } catch (err) {
      throw new PassquitoClientError(
        'invalid finish authentication response',
        makeGenericErrorCause(err),
      );
    }
    return {
      publicKeyInfo: extractPublicKeyInfo(credential),
      tokens,
    };
  }
}

// runs an abortable authentication operation.
//
// this function synchronously returns a function to abort the operation and
// a `Promise` of the credentials.
function runAbortableAuthentication(
  authenticate: (a: AbortController) => Promise<Credentials>,
) {
  let abortController: AbortController | undefined = new AbortController();
  const credentials = authenticate(abortController).finally(() => {
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

// extracts public key information from an encoded public key credential.
//
// this function should be safe either during registration or authentication,
// but no `userHandle` is available during registration.
function extractPublicKeyInfo(publicKey: PublicKeyCredential): PublicKeyInfo {
  const { userHandle } = publicKey.response as AuthenticatorAssertionResponse;
  return {
    id: publicKey.id,
    userHandle: userHandle != null ? bufferToBase64url(userHandle) : null,
    authenticatorAttachment: publicKey.authenticatorAttachment,
  };
}
