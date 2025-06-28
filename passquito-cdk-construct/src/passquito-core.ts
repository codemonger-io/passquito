import { Construct } from 'constructs';

import { CredentialsApi } from './credentials-api';
import { SsmParameters, type SsmParametersProps } from './ssm-parameters';
import { SessionStore } from './session-store';
import { UserPool } from './user-pool';

/**
 * Props for {@link PassquitoCore}.
 *
 * @beta
 */
export interface PassquitoCoreProps {
  /**
   * Allow origins for the Credentials API.
   *
   * @remarks
   *
   * No CORS preflight is performed if omitted or empty.
   */
  readonly allowOrigins?: string[];

  /**
   * Properties for {@link SsmParameters}.
   *
   * @remarks
   *
   * You can customize the parameter path for the relying party origin with
   * this option.
   */
  readonly ssmParametersProps?: SsmParametersProps;
}

/**
 * CDK Construct for the Passquito core resources.
 *
 * @beta
 */
export class PassquitoCore extends Construct {
  /** Parameters in Systems Manager (SSM) Parameter Store. */
  readonly ssmParameters: SsmParameters;

  /** Session store resources. */
  readonly sessionStore: SessionStore;

  /** User pool resources. */
  readonly userPool: UserPool;

  /** Credentials API. */
  readonly credentialsApi: CredentialsApi;

  constructor(scope: Construct, id: string, props?: PassquitoCoreProps) {
    super(scope, id);

    const { allowOrigins } = props ?? {};

    this.ssmParameters =
      new SsmParameters(this, 'SsmParameters', props?.ssmParametersProps);
    this.sessionStore = new SessionStore(this, 'SessionStore');
    this.userPool = new UserPool(this, 'UserPool', {
      ssmParameters: this.ssmParameters,
      sessionStore: this.sessionStore,
    });
    this.credentialsApi = new CredentialsApi(this, 'CredentialsApi', {
      basePath: '/auth/credentials/',
      ssmParameters: this.ssmParameters,
      sessionStore: this.sessionStore,
      userPool: this.userPool,
      allowOrigins: allowOrigins ?? [],
    });
  }

  /** Path to the SSM Parameter Store parameter that stores the relying party origin (in a URL form). */
  get rpOriginParameterPath(): string {
    return this.ssmParameters.rpOriginParameterPath;
  }

  /** User pool ID. */
  get userPoolId(): string {
    return this.userPool.userPool.userPoolId;
  }

  /** User pool client ID. */
  get userPoolClientId(): string {
    return this.userPool.userPoolClientId;
  }

  /** Internal URL of the Credentials API. */
  get credentialsApiInternalUrl(): string {
    return this.credentialsApi.internalUrl;
  }
}
