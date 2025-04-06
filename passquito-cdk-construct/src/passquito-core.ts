import { Construct } from 'constructs';

import { CredentialsApi } from './credentials-api';
import { Distribution } from './distribution';
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
  /** Parameters in Systems Manager Parameter Store (SSMPS). */
  readonly parameters: Parameters;

  /** Session store resources. */
  readonly sessionStore: SessionStore;

  /** User pool resources. */
  readonly userPool: UserPool;

  /** Credentials API. */
  readonly credentialsApi: CredentialsApi;

  /** CloudFront distribution of the Credentials API. */
  readonly distribution: Distribution;

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
    this.distribution = new Distribution(this, 'Distribution', {
      appBasePath: '/app',
      credentialsApi: this.credentialsApi,
    });
  }

  /** Path to the SSMPS parameter that stores the relying party origin (in a URL form). */
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

  /** Domain name of the CloudFront distribution. */
  get distributionDomainName(): string {
    return this.distribution.distribution.domainName;
  }

  /** URL of the app. */
  get appUrl(): string {
    return this.distribution.appUrl;
  }

  /** Name of the S3 bucketh that stores the app contents distributed via the CloudFront distribution. */
  get appContentsBucketName(): string {
    return this.distribution.appBucket.bucketName;
  }
}
