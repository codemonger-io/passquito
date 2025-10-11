import { aws_dynamodb as dynamodb } from 'aws-cdk-lib';
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
   * Base path for the Credentials API.
   *
   * @remarks
   *
   * Must start with a slash (`/`).
   * A trailing slash is optional.
   *
   * `/auth/credentials/` if omitted.
   */
  readonly basePath?: string;

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

  /**
   * Billing option for the DynamoDB table that stores sessions.
   *
   * @remarks
   *
   * On-demand (PAY_PER_REQUEST) without caps by default.
   */
  readonly billingForSessionTable?: dynamodb.Billing;

  /**
   * Billing option for the DynamoDB table that stores credentials.
   *
   * @remarks
   *
   * On-demand (PAY_PER_REQUEST) without caps by default.
   */
  readonly billingForCredentialTable?: dynamodb.Billing;
}

// default base path for the Credentials API.
const DEFAULT_BASE_PATH = '/auth/credentials/';

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

    const {
      allowOrigins,
      basePath,
      billingForCredentialsTable,
      billingForSessionTable,
    } = props ?? {};

    this.ssmParameters =
      new SsmParameters(this, 'SsmParameters', props?.ssmParametersProps);
    this.sessionStore = new SessionStore(this, 'SessionStore', {
      billing: billingForSessionTable ?? dynamodb.Billing.onDemand(),
    });
    this.userPool = new UserPool(this, 'UserPool', {
      ssmParameters: this.ssmParameters,
      sessionStore: this.sessionStore,
      billing: billingForCredentialTable ?? dynamodb.Billing.onDemand(),
    });
    this.credentialsApi = new CredentialsApi(this, 'CredentialsApi', {
      basePath: basePath ?? DEFAULT_BASE_PATH,
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
