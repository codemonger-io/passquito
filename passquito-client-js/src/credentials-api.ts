import type { CognitoTokens, UserInfo, VerifiedUserInfo } from './types';

/**
 * Registration session.
 *
 * @beta
 */
export interface RegistrationSession {
  /** Session ID. */
  sessionId: string;

  /** Credential creation options for a public key. */
  credentialCreationOptions: CredentialCreationOptions;
}

/**
 * Authentication session.
 *
 * @beta
 */
export interface AuthenticationSession {
  /** Session ID. */
  sessionId: string;

  /** Credential request options for a public key. */
  credentialRequestOptions: CredentialRequestOptions;
}

/**
 * Service that provides access to the Credentials API.
 *
 * @beta
 */
export interface CredentialsApi {
  /**
   * Starts a registration session of a new user.
   */
  startRegistration(userInfo: UserInfo): Promise<RegistrationSession>;

  /**
   * Starts a registration session of a new credential for an existing user.
   */
  startRegistrationForVerifiedUser(userInfo: VerifiedUserInfo): Promise<RegistrationSession>;

  /**
   * Finishes a registration session.
   *
   * @param sessionId - Session ID returned from
   *   {@link CredentialsApi.startRegistration|startRegistration} or
   *   {@link CredentialsApi.startRegistrationForVerifiedUser|startRegistrationForVerifiedUser)}.
   */
  finishRegistration(sessionId: string, credential: PublicKeyCredential): Promise<void>;

  /**
   * Returns a credential request options for a discoverable credential.
   */
  getDiscoverableCredentialRequestOptions(): Promise<CredentialRequestOptions>;

  /**
   * Starts an authentication session.
   *
   * @remarks
   *
   * You have to call this function even if you are conducting authentication
   * with a discoverable credential.
   *
   * @param userId - Passquito user ID.
   */
  startAuthentication(userId: string): Promise<AuthenticationSession>;

  /**
   * Finishes an authentication session.
   */
  finishAuthentication(
    sessionId: string,
    userId: string,
    credential: PublicKeyCredential,
  ): Promise<CognitoTokens>;

  /**
   * Refreshes the Cognito tokens associated with a given refresh token.
   *
   * @returns  Refreshed Cognito tokens. `undefined` if the refresh token is
   *   invalid or expired.
   */
  refreshTokens(refreshToken: string): Promise<CognitoTokens | undefined>;
}
