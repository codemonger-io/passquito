/** Provides Web Authentication access. */

/** Web Authentication access. */
export interface UseWebauth {
  /** Base URL of the Web Authentication endpoints. */
  readonly baseUrl: string;
}

/** Uses Web Authentication. */
export const useWebauthn = (): UseWebauth => {
  const baseUrl = `/auth/`;
  return { baseUrl };
}
