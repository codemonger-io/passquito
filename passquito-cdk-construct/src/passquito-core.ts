import { Construct } from 'constructs';

import { CredentialsApi } from './credentials-api';
import { Parameters } from './parameters';
import { SessionStore } from './session-store';
import { UserPool } from './user-pool';

/**
 * Props for {@link PassquitoCore}.
 *
 * @beta
 */
export interface PassquitoCoreProps {
  /**
   * Domain name of the distribution.
   *
   * @remarks
   *
   * May be `undefined` until the stack is first deployed.
   */
  readonly distributionDomainName?: string;
}

/**
 * CDK Construct for the Passquito core resources.
 *
 * @beta
 */
export class PassquitoCore extends Construct {
  /** Parameters in Systems Manager (SSM) Parameter Store. */
  readonly parameters: Parameters;

  /** Session store resources. */
  readonly sessionStore: SessionStore;

  /** User pool resources. */
  readonly userPool: UserPool;

  /** Credentials API. */
  readonly credentialsApi: CredentialsApi;

  constructor(scope: Construct, id: string, props?: PassquitoCoreProps) {
    super(scope, id);

    const { distributionDomainName } = props ?? {};

    this.parameters = new Parameters(this, 'Parameters');
    this.sessionStore = new SessionStore(this, 'SessionStore');
    this.userPool = new UserPool(this, 'UserPool', {
      parameters: this.parameters,
      sessionStore: this.sessionStore,
    });
    this.credentialsApi = new CredentialsApi(this, 'CredentialsApi', {
      basePath: '/auth/credentials/',
      parameters: this.parameters,
      sessionStore: this.sessionStore,
      userPool: this.userPool,
      allowOrigins: [
        'http://localhost:5173',
        ...(distributionDomainName
          ? [`https://${distributionDomainName}`]
          : []),
      ],
    });
  }

  /** Path to the SSM Parameter Store parameter that stores the relying party origin (in a URL form). */
  get rpOriginParameterPath(): string {
    return this.parameters.rpOriginParameter.parameterName;
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
