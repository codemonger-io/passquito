/**
 * User information for registration.
 *
 * @remarks
 *
 * Neither {@link UserInfo.username|username} nor
 * {@link UserInfo.displayName|displayName} have to be unique.
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
 * Registered user information.
 *
 * @beta
 */
export interface RegisteredUserInfo {
  /** Unique ID of the registered user. */
  userId: string;
}

/**
 * Information about a public key.
 *
 * @beta
 */
export interface PublicKeyInfo {
  /** Unique ID of the public key. */
  id: string;

  /** User handle. Should be the Passquito user ID. */
  userHandle?: string | null;

  /** Authenticator attachment status. */
  authenticatorAttachment?: string | null;
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
   * Activation time represented as the number of milliseconds elapsed since
   * 00:00:00 on January 1, 1970 in UTC.
   *
   * @remarks
   *
   * Expiration time of tokens is approximately this value plus
   * {@link CognitoTokens.expiresIn|expiresIn} × 1000.
   */
  activatedAt: number;
}

/**
 * Returns if a given value is a {@link PublicKeyInfo}.
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
 * Returns if a given value is a {@link CognitoTokens}.
 *
 * @beta
 */
export function isCognitoTokens(value: unknown): value is CognitoTokens {
  if (value == null || typeof value !== 'object') {
    return false;
  }
  const maybeTokens = value as CognitoTokens;
  return typeof maybeTokens.idToken === 'string' &&
    typeof maybeTokens.accessToken === 'string' &&
    typeof maybeTokens.refreshToken === 'string' &&
    typeof maybeTokens.activatedAt === 'number';
}
