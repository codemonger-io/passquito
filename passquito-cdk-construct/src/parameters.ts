import { GhostStringParameter } from '@codemonger-io/cdk-ghost-string-parameter';
import { Construct } from 'constructs';

/**
 * CDK construct that declares parameters in Parameter Store on AWS Systems
 * Manager.
 *
 * @remarks
 *
 * This construct won't actually provision parameters.
 */
export class Parameters extends Construct {
  /** Origin (URL) of the relying party. */
  readonly rpOriginParameter: GhostStringParameter;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    this.rpOriginParameter = new GhostStringParameter(this, {
      parameterName: '/passkey-test/RP_ORIGIN',
    });
  }
}
