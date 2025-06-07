import { App, Stack } from 'aws-cdk-lib';

import { SsmParameters } from '../src/ssm-parameters';

describe('SsmParameters', () => {
  let stack: Stack;

  beforeEach(() => {
    const app = new App();
    stack = new Stack(app, 'TestStack');
  });

  it('should link a parameter at "/passquito/default/RP_ORIGIN" by default', () => {
    const parameters = new SsmParameters(stack, 'SsmParameters');
    expect(parameters.rpOriginParameterPath).toBe('/passquito/default/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/production/RP_ORIGIN" when config="production"', () => {
    const parameters = new SsmParameters(stack, 'SsmParameters', {
      config: 'production',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/production/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/example/default/RP_ORIGIN" when group="example"', () => {
    const parameters = new SsmParameters(stack, 'SsmParameters', {
      group: 'example',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/example/default/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/test/development/RP_ORIGIN" when group="test" and config="development"', () => {
    const parameters = new SsmParameters(stack, 'SsmParameters', {
      group: 'test',
      config: 'development',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/test/development/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/default/RP_ORIGIN" when config=""', () => {
    const parameters = new SsmParameters(stack, 'SsmParameters', {
      config: '',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/default/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/default/RP_ORIGIN" when group=""', () => {
    const parameters = new SsmParameters(stack, 'SsmParameters', {
      group: '',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/default/RP_ORIGIN');
  });
});
