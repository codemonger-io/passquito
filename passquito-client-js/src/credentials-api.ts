import type {
  CognitoTokens,
  RegisteredUserInfo,
  UserInfo,
  VerifiedUserInfo,
} from './types';

/**
 * Response from the Credentials API.
 *
 * @typeParam T - Type of the response body.
 *
 * @beta
 */
export interface ApiResponse<T> {
  /**
   * Whether the API call has succeeded.
   * See the {@link https://developer.mozilla.org/en-US/docs/Web/API/Response/ok | `ok` property of the Fetch API Response}.
   */
  readonly ok: boolean;

  /**
   * Status code of the response.
   * See the {@link https://developer.mozilla.org/en-US/docs/Web/API/Response/status | `status` property of the Fetch API Response}.
   */
  readonly status: number;

  /**
   * Parses the response body.
   *
   * @remarks
   *
   * Calling this function two or more times, or after
   * {@link ApiResponse.text | text} will fail.
   *
   * @throws Error
   *
   *   If the response body does not represent `T`.
   *
   * @throws TypeError
   *
   *   If the response body has already been read.
   */
  parse(): Promise<T>;

  /**
   * Text representation of the response body.
   * See the {@link https://developer.mozilla.org/en-US/docs/Web/API/Response/text | `text` method of the Fetch API Response}.
   *
   * @remarks
   *
   * Calling this function two or more times, or after
   * {@link ApiResponse.parse | parse} will fail.
   *
   * @throws TypeError
   *
   *   If the response body has already been read.
   */
  text(): Promise<string>;
}

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
  startRegistration(userInfo: UserInfo): Promise<ApiResponse<RegistrationSession>>;

  /**
   * Starts a registration session of a new credential for an existing user.
   */
  startRegistrationForVerifiedUser(userInfo: VerifiedUserInfo): Promise<ApiResponse<RegistrationSession>>;

  /**
   * Finishes a registration session.
   *
   * @param sessionId - Session ID returned from
   *   {@link CredentialsApi.startRegistration|startRegistration} or
   *   {@link CredentialsApi.startRegistrationForVerifiedUser|startRegistrationForVerifiedUser)}.
   *
   * @returns
   *
   *   Registered user information including the unique user ID issued by Passquito.
   */
  finishRegistration(
    sessionId: string,
    credential: PublicKeyCredential,
  ): Promise<ApiResponse<RegisteredUserInfo>>;

  /**
   * Returns a credential request options for a discoverable credential.
   */
  getDiscoverableCredentialRequestOptions(): Promise<ApiResponse<CredentialRequestOptions>>;

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
  startAuthentication(userId: string): Promise<ApiResponse<AuthenticationSession>>;

  /**
   * Finishes an authentication session.
   */
  finishAuthentication(
    sessionId: string,
    userId: string,
    credential: PublicKeyCredential,
  ): Promise<ApiResponse<CognitoTokens>>;

  /**
   * Refreshes the Cognito tokens associated with a given refresh token.
   *
   * @returns
   *
   *   {@link ApiResponse} that will be resolved with refreshed Cognito tokens.
   *   Check the `ok` property to see if the operation has succeeded.
   *   If not `ok`, inspect the `status` property for the reason for failure;
   *   e.g., you will get `401` for an invalid or expired refresh token.
   */
  refreshTokens(refreshToken: string): Promise<ApiResponse<CognitoTokens>>;
}
