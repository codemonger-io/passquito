import { bufferToBase64url } from '@github/webauthn-json/extended';

import type { CredentialsApi, RegistrationSession } from './credentials-api';
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
   */
  async doRegistrationCeremony(userInfo: UserInfo): Promise<PublicKeyInfo> {
    return this.runRegistrationSession(
      await this.credentialsApi.startRegistration(userInfo),
    );
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
   */
  async doRegistrationCeremonyForVerifiedUser(userInfo: VerifiedUserInfo): Promise<PublicKeyInfo> {
    return this.runRegistrationSession(
      await this.credentialsApi.startRegistrationForVerifiedUser(userInfo),
    );
  }

  // runs a given registration session.
  private async runRegistrationSession(session: RegistrationSession): Promise<PublicKeyInfo> {
    const credential = await navigator.credentials.create(
      session.credentialCreationOptions,
    ) as (PublicKeyCredential | null);
    if (credential == null) {
      throw new Error('failed to create a new credential');
    }
    const { userId } = await this.credentialsApi.finishRegistration(
      session.sessionId,
      credential,
    );
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
    const options = await this.credentialsApi.getDiscoverableCredentialRequestOptions();
    const credential = await navigator.credentials.get({
      ...options,
      mediation: 'conditional',
      signal: abortController.signal,
    }) as (PublicKeyCredential | null);
    if (credential == null) {
      throw new Error('public key credential must be provided');
    }
    const publicKeyInfo = extractPublicKeyInfo(credential);
    const { userHandle } = publicKeyInfo;
    if (userHandle == null) {
      throw new Error('authenticator must return userHandle');
    }
    const { sessionId } = await this.credentialsApi.startAuthentication(userHandle);
    // ignores other parameters for discoverable credentials
    const tokens = await this.credentialsApi.finishAuthentication(
      sessionId,
      userHandle,
      credential,
    );
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
    const session = await this.credentialsApi.startAuthentication(userId);
    const credential = await navigator.credentials.get({
      ...session.credentialRequestOptions,
      mediation: 'conditional',
      signal: abortController.signal,
    }) as (PublicKeyCredential | null);
    if (credential == null) {
      throw new Error('public key credential must be provided');
    }
    const tokens = await this.credentialsApi.finishAuthentication(
      session.sessionId,
      userId,
      credential,
    );
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
