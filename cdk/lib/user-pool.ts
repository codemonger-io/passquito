import * as path from 'node:path';
import {
  Duration,
  RemovalPolicy,
  aws_cognito as cognito,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import { RustFunction } from 'cargo-lambda-cdk';
import { Construct } from 'constructs';

/** CDK construct that provisions the user pool. */
export class UserPool extends Construct {
  /** User pool. */
  readonly userPool: cognito.UserPool;
  /** User pool client. */
  readonly userPoolClient: cognito.UserPoolClient;
  /** Cognito trigger Lambda for the user pool. */
  readonly userPoolTriggerLambda: lambda.IFunction;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    this.userPoolTriggerLambda = new RustFunction(this, 'CognitoTriggerLambda', {
      manifestPath: path.join('lambda', 'user-pool-triggers', 'Cargo.toml'),
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(5),
    });

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: false,
      signInAliases: {
        username: true,
      },
      lambdaTriggers: {
        defineAuthChallenge: this.userPoolTriggerLambda,
        createAuthChallenge: this.userPoolTriggerLambda,
        verifyAuthChallengeResponse: this.userPoolTriggerLambda,
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
