/**
 * Configures the relying party origin.
 *
 * @remarks
 *
 * Obtains the domain name of the CloudFront distribution from the
 * CloudFormation stack and stores it to Parameter Store on AWS Systems Manager.
 */

import { PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { getStackOutputs } from '../lib/stack-outputs';

const STACK_NAME = 'passkey-test';

async function run(originUrl?: string) {
  const stackOutputs = await getStackOutputs(STACK_NAME);
  await setSsmParameter(
    stackOutputs.rpOriginParameterPath,
    originUrl || `https://${stackOutputs.distributionDomainName}`,
  );
}

async function setSsmParameter(parameterName: string, value: string) {
  console.log(`putting parameter: ${parameterName} = ${value}`);
  const client = new SSMClient({});
  await client.send(new PutParameterCommand({
    Name: parameterName,
    Value: value,
    Type: 'String',
    Overwrite: true,
  }));
}

yargs(hideBin(process.argv))
  .command(
    '$0 [origin]',
    'set relying party (RP) origin SSM parameter',
    (yargs) => yargs
      .positional('origin', {
        describe: 'RP origin URL. Use CloudFront distribution URL by default',
        type: 'string',
        default: undefined,
      }),
    async ({ origin }) => {
      try {
        run(origin)
      } catch (err) {
        console.error(err);
      }
    },
  )
  .help()
  .argv;
