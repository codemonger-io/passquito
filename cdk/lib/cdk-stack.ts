import { CfnOutput, Stack } from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import type { Construct } from 'constructs';

import { PassquitoCore } from '@codemonger-io/passquito-cdk-construct';

import { Distribution } from './distribution';

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

    const passquito = new PassquitoCore(this, 'Passquito', {
      distributionDomainName: props.distributionDomainName,
      ssmParametersProps: {
        group: 'passquito-demo',
        config: 'development',
      },
    });
    const distribution = new Distribution(this, 'Distribution', {
      appBasePath: '/app',
      credentialsApi: passquito.credentialsApi,
    });

    new CfnOutput(this, 'RpOriginParameterPath', {
      description: 'Parameter Store parameter path for the relying party origin (URL)',
      value: passquito.rpOriginParameterPath,
    });
    new CfnOutput(this, 'UserPoolId', {
      description: 'ID of the Cognito user pool',
      value: passquito.userPoolId,
    });
    new CfnOutput(this, 'UserPoolClientId', {
      description: 'ID of the Cognito user pool client',
      value: passquito.userPoolClientId,
    });
    new CfnOutput(this, 'CredentialsApiInternalUrl', {
      description: 'URL of the Credentials API for internal tests',
      value: passquito.credentialsApiInternalUrl,
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
