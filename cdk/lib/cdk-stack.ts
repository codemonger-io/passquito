import { CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { UserPool } from './user-pool';

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const userPool = new UserPool(this, 'UserPool');

    new CfnOutput(this, 'UserPoolId', {
      description: 'ID of the Cognito user pool',
      value: userPool.userPool.userPoolId,
    });
    new CfnOutput(this, 'UserPoolClientId', {
      description: 'ID of the Cognito user pool client',
      value: userPool.userPoolClient.userPoolClientId,
    });
  }
}
