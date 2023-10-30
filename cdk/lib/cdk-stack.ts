import { CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { SessionStore } from './session-store';
import { CredentialsApi } from './credentials-api';
import { UserPool } from './user-pool';

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const userPool = new UserPool(this, 'UserPool');
    const sessionStore = new SessionStore(this, 'SessionStore');
    const credentialsApi = new CredentialsApi(this, 'CredentialsApi', {
      basePath: '/auth/credentials/',
      sessionStore,
      userPool,
    });

    new CfnOutput(this, 'UserPoolId', {
      description: 'ID of the Cognito user pool',
      value: userPool.userPool.userPoolId,
    });
    new CfnOutput(this, 'UserPoolClientId', {
      description: 'ID of the Cognito user pool client',
      value: userPool.userPoolClient.userPoolClientId,
    });
    new CfnOutput(this, 'CredentialsApiInternalUrl', {
      description: 'URL of the Credentials API for internal tests',
      value: credentialsApi.internalUrl,
    });
  }
}
