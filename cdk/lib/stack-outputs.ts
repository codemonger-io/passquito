import {
  CloudFormationClient,
  DescribeStacksCommand,
} from '@aws-sdk/client-cloudformation';

/** Outputs from the CloudFormation stack. */
export interface StackOutputs {
  /** Domain name of the CloudFront distribution. */
  readonly distributionDomainName: string;

  /**
   * Path to the Parameter Store parameter that stores the relying party origin
   * (URL).
   */
  readonly rpOriginParameterPath: string;
}

/** Obtains the outputs of the CloudFormation stack. */
export async function getStackOutputs(
  stackName: string,
): Promise<StackOutputs> {
  const client = new CloudFormationClient({});
  const res = await client.send(new DescribeStacksCommand({
    StackName: stackName,
  }));
  const stack = res.Stacks?.[0];
  if (stack == null) {
    throw new Error(`no such stack: ${stackName}`);
  }
  const outputs = stack.Outputs;
  if (outputs == null) {
    throw new Error(`stack has no outputs: ${stackName}`);
  }
  const outputMap = new Map<string, string>();
  for (const output of outputs) {
    if (output.OutputKey != null && output.OutputValue != null) {
      outputMap.set(output.OutputKey, output.OutputValue);
    }
  }
  const distributionDomainName = outputMap.get('DistributionDomainName');
  if (distributionDomainName == null) {
    throw new Error('missing "DistributionDomainName" in stack outputs');
  }
  const rpOriginParameterPath = outputMap.get('RpOriginParameterPath');
  if (rpOriginParameterPath == null) {
    throw new Error('missing "RpOriginParameterPath" in stack outputs');
  }
  return {
    distributionDomainName,
    rpOriginParameterPath,
  };
}
