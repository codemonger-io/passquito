/**
 * User information for registration.
 *
 * @remarks
 *
 * Neither `username` nor `displayName` have to be unique.
 * They are for display purposes only.
 *
 * @beta
 */
export interface UserInfo {
  /** Username. Must not be empty. */
  username: string;

  /** Display name. */
  displayName: string;
}

/**
 * Information on a verified user who bears an ID token.
 *
 * @beta
 */
export interface VerifiedUserInfo {
  /** ID token of the verified user. */
  idToken: string;

  /** User information. */
  userInfo: UserInfo;
}

/**
 * Cognito tokens.
 *
 * @beta
 */
export interface CognitoTokens {
  /** ID token. */
  idToken: string;

  /** Access token. */
  accessToken: string;

  /** Refresh token. */
  refreshToken: string;

  /** Duration of the token in seconds. */
  expiresIn: number;

  /**
   * Activation time represented as the number of milliseconds since 00:00:00
   * on January 1, 1970 in UTC.
   *
   * @remarks
   *
   * Expiration time of tokens is approximately this value plus `expiresIn` ×
   * 1000.
   */
  activatedAt: number;
}
