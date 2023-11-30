import { CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { CredentialsApi } from './credentials-api';
import { Distribution } from './distribution';
import { Parameters } from './parameters';
import { SessionStore } from './session-store';
import { UserPool } from './user-pool';

export interface CdkStackProps extends StackProps {
  /**
   * Domain name of the distribution.
   *
   * @remarks
   *
   * `undefined` until the stack is first deployed.
   */
  readonly distributionDomainName?: string;
}

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string, props: CdkStackProps) {
    super(scope, id, props);

    const parameters = new Parameters(this, 'Parameters');
    const sessionStore = new SessionStore(this, 'SessionStore');
    const userPool = new UserPool(this, 'UserPool', {
      parameters,
      sessionStore,
    });
    const credentialsApi = new CredentialsApi(this, 'CredentialsApi', {
      basePath: '/auth/credentials/',
      parameters,
      sessionStore,
      userPool,
      allowOrigins: [
        'http://localhost:5173',
        ...(props.distributionDomainName
          ? [`https://${props.distributionDomainName}`]
          : []),
      ],
    });
    const distribution = new Distribution(this, 'Distribution', {
      appBasePath: '/app',
      credentialsApi,
    });

    new CfnOutput(this, 'RpOriginParameterPath', {
      description: 'Parameter Store parameter path for the relying party origin (URL)',
      value: parameters.rpOriginParameter.parameterName,
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
    new CfnOutput(this, 'DistributionDomainName', {
      description: 'Distribution domain name',
      value: distribution.distribution.domainName,
    });
    new CfnOutput(this, 'AppUrl', {
      description: 'URL of the app',
      value: distribution.appUrl,
    });
    new CfnOutput(this, 'AppContentsBucketName', {
      description: 'Name of the S3 bucket that stores the app contents',
      value: distribution.appBucket.bucketName,
    });
  }
}
