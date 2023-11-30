#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CdkStack } from '../lib/cdk-stack';
import { getStackOutputs } from '../lib/stack-outputs';

// `distributionDomainName` is specified to allow origins of the CORS
// configuration for the credentials API.
//
// It won't be available until the stack is first deployed. So you have to
// deploy the stack twice to activate the CORS configuration.
function run(distributionDomainName?: string) {
  const app = new cdk.App();
  new CdkStack(app, 'passkey-test', {
    distributionDomainName,
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_DEFAULT_REGION,
    },
    tags: {
      project: 'experiment',
    },
  });
}

getStackOutputs('passkey-test')
  .then((outputs) => {
    run(outputs.distributionDomainName);
  })
  .catch((err) => {
    console.log('no stack seems deployed');
    run();
  });
