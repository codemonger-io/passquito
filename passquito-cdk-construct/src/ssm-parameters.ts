import { GhostStringParameter } from '@codemonger-io/cdk-ghost-string-parameter';
import { Construct } from 'constructs';

/**
 * Props for {@link SsmParameters}.
 *
 * @beta
 */
export interface SsmParametersProps {
  /**
   * Group name included in the parameter path.
   * No group segment by default.
   */
  readonly group?: string;

  /**
   * Configuration name included in the parameter path.
   * "default" by default.
   */
  readonly config?: string;
}

/**
 * CDK construct that declares parameters in Parameter Store on AWS Systems
 * Manager.
 *
 * @remarks
 *
 * This construct won't actually provision parameters.
 *
 * The parameter path will be either of:
 * - `/passquito/{config}/RP_ORIGIN` without {@link SsmParametersProps.group}
 * - `/passquito/{group}/{config}/RP_ORIGIN` with {@link SsmParametersProps.group}
 *
 * `config` is `"default"` by default.
 *
 * @beta
 */
export class SsmParameters extends Construct {
  /** Origin (URL) of the relying party. */
  readonly rpOriginParameter: GhostStringParameter;

  constructor(scope: Construct, id: string, props: SsmParametersProps = {}) {
    super(scope, id);

    const config = props.config || 'default';
    const groupSegment = props.group ? `${props.group}/` : '';

    this.rpOriginParameter = new GhostStringParameter(this, {
      parameterName: `/passquito/${groupSegment}${config}/RP_ORIGIN`,
    });
  }

  /** Parameter path for the relying party origin. */
  get rpOriginParameterPath(): string {
    return this.rpOriginParameter.parameterName;
  }
}
