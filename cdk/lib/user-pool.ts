import * as path from 'node:path';
import {
  Duration,
  RemovalPolicy,
  aws_cognito as cognito,
  aws_dynamodb as dynamodb,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import { RustFunction } from 'cargo-lambda-cdk';
import { Construct } from 'constructs';

import type { Parameters } from './parameters';
import type { SessionStore } from './session-store';

/** Properties for `UserPool` */
export interface UserPoolProps {
  /** Parameters in Parameter Store on AWS Systems Manager. */
  readonly parameters: Parameters;

  /** Session store. */
  readonly sessionStore: SessionStore;
}

/**
 * CDK construct that provisions the user pool.
 *
 * ## Credential table
 *
 * ### Keys and attributes
 *
 * - Partition key: `pk`
 * - Sort key: `sk`
 *
 * Global secondary index:
 * - Partition key: `credentialId`
 *
 * #### User's public key credential
 *
 * - `pk`: "user#<user ID>"
 *     - `<user ID>` is the "base64url"-encoded user handle (unique ID)
 * - `sk`: "credential#<credential ID>"
 *     - `<credential ID>` is the "base64url"-encoded credential ID
 * - `credentialId`: "<credential ID>"
 * - `credential`: serialized JSON representation of [`Passkey`]
 * - `cognitoSub`: Cognito sub ID
 * - `createdAt`: "<yyyy-mm-ddTHH:MM:SS.SSSSSSZ>"
 *     - timestamp when the credential was registered
 * - `updatedAt`: "<yyyy-mm-ddTHH:MM:SS.SSSSSSZ>"
 *     - timestamp when the credential was last updated
 */
export class UserPool extends Construct {
  /** User pool. */
  readonly userPool: cognito.UserPool;
  /** User pool client. */
  readonly userPoolClient: cognito.UserPoolClient;
  /** DynamoDB table for credentials. */
  readonly credentialTable: dynamodb.TableV2;
  /** Cognito trigger Lambda for the user pool. */
  readonly userPoolTriggerLambda: lambda.IFunction;

  constructor(scope: Construct, id: string, props: UserPoolProps) {
    super(scope, id);

    const { parameters, sessionStore } = props;

    this.credentialTable = new dynamodb.TableV2(this, 'CredentialTable', {
      partitionKey: {
        name: 'pk',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'sk',
        type: dynamodb.AttributeType.STRING,
      },
      globalSecondaryIndexes: [
        {
          indexName: 'CredentialIdIndex',
          partitionKey: {
            name: 'credentialId',
            type: dynamodb.AttributeType.STRING,
          },
          projectionType: dynamodb.ProjectionType.KEYS_ONLY,
        },
      ],
      billing: dynamodb.Billing.provisioned({
        readCapacity: dynamodb.Capacity.fixed(1),
        writeCapacity: dynamodb.Capacity.autoscaled({
          maxCapacity: 1,
        }),
      }),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.userPoolTriggerLambda = new RustFunction(
      this,
      'CognitoTriggerLambda',
      {
        manifestPath: path.join('lambda', 'authentication', 'Cargo.toml'),
        binaryName: 'user-pool-triggers',
        architecture: lambda.Architecture.ARM_64,
        environment: {
          CREDENTIAL_TABLE_NAME: this.credentialTable.tableName,
          SESSION_TABLE_NAME: sessionStore.sessionTable.tableName,
          RP_ORIGIN_PARAMETER_PATH: parameters.rpOriginParameter.parameterName,
        },
        memorySize: 128,
        timeout: Duration.seconds(5),
      },
    );
    this.credentialTable.grantReadWriteData(this.userPoolTriggerLambda);
    parameters.rpOriginParameter.grantRead(this.userPoolTriggerLambda);
    sessionStore.sessionTable.grantReadWriteData(this.userPoolTriggerLambda);

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: false,
      signInAliases: {
        // username equals the passkey user handle ("base64url"-encoded UUID)
        username: true,
      },
      lambdaTriggers: {
        defineAuthChallenge: this.userPoolTriggerLambda,
        createAuthChallenge: this.userPoolTriggerLambda,
        verifyAuthChallengeResponse: this.userPoolTriggerLambda,
      },
      // password policy should not be restrictive over character class usage
      // because passwords are randomly generated
      passwordPolicy: {
        minLength: 32, // equivalent to Base64 encoded 24 byte sequence
        requireDigits: false,
        requireLowercase: false,
        requireSymbols: false,
        requireUppercase: false,
        tempPasswordValidity: Duration.days(1),
      },
      accountRecovery: cognito.AccountRecovery.NONE,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.userPoolClient = this.userPool.addClient('UserPoolClient', {
      authFlows: {
        custom: true,
      },
      disableOAuth: true,
      preventUserExistenceErrors: true,
      authSessionValidity: Duration.minutes(3),
      accessTokenValidity: Duration.minutes(30),
      idTokenValidity: Duration.minutes(30),
      refreshTokenValidity: Duration.days(30),
    });
  }
}
