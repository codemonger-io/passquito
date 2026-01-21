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
 * Error cause related to an HTTP response of the Credentials API.
 *
 * @remarks
 *
 * A variant of {@link PassquitoClientErrorCause}.
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
  };
}

/**
 * Generic error cause.
 *
 * @remarks
 *
 * A variant of {@link PassquitoClientErrorCause}.
 *
 * Any error thrown during processing of {@link PassquitoClient} is wrapped
 * in this variant.
 *
 * @beta
 */
export interface PassquitoClientErrorCauseGeneric {
  type: 'generic';

  error: unknown;
}

/**
 * Wraps an error with {@link PassquitoClientErrorCauseGeneric}.
 *
 * @beta
 */
function makeGenericErrorCause(error: unknown): PassquitoClientErrorCauseGeneric {
  return {
    type: 'generic',
    error,
  };
}

/**
 * Error thrown by {@link PassquitoClient}.
 *
 * @beta
 */
export class PassquitoClientError extends Error {
  /**
   * Cause of the error.
   *
   * @remarks
   *
   * Overrides the type of the built-in `cause` property so that users can
   * access `cause` with proper typing.
   */
  declare readonly cause?: PassquitoClientErrorCause;

  constructor(message: string, cause?: PassquitoClientErrorCause) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = 'PassquitoClientError';
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
   * @throws PassquitoClientError
   *
   *   When the registration ceremony fails.
   */
  async doRegistrationCeremony(userInfo: UserInfo): Promise<PublicKeyInfo> {
    try {
      const startRes = await this.credentialsApi.startRegistration(userInfo);
      if (!startRes.ok) {
        throw new PassquitoClientError(
          'failed to start registration session',
          makeCredentialsApiErrorCause(startRes),
        );
      }
      return this.runRegistrationSession(await startRes.parse());
    } catch (err) {
      if (err instanceof PassquitoClientError) {
        throw err;
      }
      throw new PassquitoClientError(
        'failed to conduct registration ceremony',
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
   * @throws PassquitoClientError
   *
   *   When the registration ceremony fails.
   */
  async doRegistrationCeremonyForVerifiedUser(userInfo: VerifiedUserInfo): Promise<PublicKeyInfo> {
    try {
      const startRes = await this.credentialsApi.startRegistrationForVerifiedUser(userInfo);
      if (!startRes.ok) {
        throw new PassquitoClientError(
          'failed to start registration session for verified user',
          makeCredentialsApiErrorCause(startRes),
        );
      }
      return this.runRegistrationSession(await startRes.parse());
    } catch (err) {
      // wraps any error with PassquitoClientError unless it's already a PassquitoClientError.
      if (err instanceof PassquitoClientError) {
        throw err;
      }
      throw new PassquitoClientError(
        'failed to conduct registration ceremony for verified user',
        makeGenericErrorCause(err),
      );
    }
  }

  // runs a given registration session.
  private async runRegistrationSession(session: RegistrationSession): Promise<PublicKeyInfo> {
    try {
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
      const { userId } = await finishRes.parse();
      const publicKeyInfo = extractPublicKeyInfo(credential);
      // NOTE: no `userHandle` is available in an attestation (registration)
      // response, so we substitute it with the user ID obtained from the
      // Credentials API.
      publicKeyInfo.userHandle = userId;
      return publicKeyInfo;
    } catch (err) {
      // wraps any error with PassquitoClientError unless it's already a PassquitoClientError.
      if (err instanceof PassquitoClientError) {
        throw err;
      }
      throw new PassquitoClientError(
        'failed to run registration session',
        makeGenericErrorCause(err),
      );
    }
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
   * The `Promise` of the credentials will reject with
   * {@link PassquitoClientError} when the authentication ceremony fails.
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
   * The `Promise` of the credentials will reject with
   * {@link PassquitoClientError} when the authentication ceremony fails.
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
    try {
      const getOptionsRes = await this.credentialsApi.getDiscoverableCredentialRequestOptions();
      if (!getOptionsRes.ok) {
        throw new PassquitoClientError(
          'failed to get discoverable credential request options',
          makeCredentialsApiErrorCause(getOptionsRes),
        );
      }
      const options = await getOptionsRes.parse();
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
      const { sessionId } = await startRes.parse();
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
      const tokens = await finishRes.parse();
      return {
        publicKeyInfo,
        tokens,
      };
    } catch (err) {
      // wraps any error with PassquitoClientError unless it's already a PassquitoClientError.
      if (err instanceof PassquitoClientError) {
        throw err;
      }
      throw new PassquitoClientError(
        'failed to conduct authentication ceremony',
        makeGenericErrorCause(err),
      );
    }
  }

  // conducts an authentication ceremony for a given user with a given
  // AbortController.
  private async doAbortableAuthenticationCeremonyForUser(
    userId: string,
    abortController: AbortController,
  ) {
    try {
      const startRes = await this.credentialsApi.startAuthentication(userId);
      if (!startRes.ok) {
        throw new PassquitoClientError(
          'failed to start authentication',
          makeCredentialsApiErrorCause(startRes),
        );
      }
      const session = await startRes.parse();
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
      const tokens = await finishRes.parse();
      return {
        publicKeyInfo: extractPublicKeyInfo(credential),
        tokens,
      };
    } catch (err) {
      // wraps any error with PassquitoClientError unless it's already a PassquitoClientError.
      if (err instanceof PassquitoClientError) {
        throw err;
      }
      throw new PassquitoClientError(
        'failed to conduct authentication ceremony for user',
        makeGenericErrorCause(err),
      );
    }
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
