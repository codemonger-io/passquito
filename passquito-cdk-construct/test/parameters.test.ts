import { App, Stack } from 'aws-cdk-lib';
import { Parameters } from '../src/parameters';

describe('Parameters', () => {
  let stack: Stack;

  beforeEach(() => {
    const app = new App();
    stack = new Stack(app, 'TestStack');
  });

  it('should link a parameter at "/passquito/default/RP_ORIGIN" by default', () => {
    const parameters = new Parameters(stack, 'Parameters');
    expect(parameters.rpOriginParameterPath).toBe('/passquito/default/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/production/RP_ORIGIN" when config="production"', () => {
    const parameters = new Parameters(stack, 'Parameters', {
      config: 'production',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/production/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/example/default/RP_ORIGIN" when group="example"', () => {
    const parameters = new Parameters(stack, 'Parameters', {
      group: 'example',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/example/default/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/test/development/RP_ORIGIN" when group="test" and config="development"', () => {
    const parameters = new Parameters(stack, 'Parameters', {
      group: 'test',
      config: 'development',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/test/development/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/default/RP_ORIGIN" when config=""', () => {
    const parameters = new Parameters(stack, 'Parameters', {
      config: '',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/default/RP_ORIGIN');
  });

  it('should link a parameter at "/passquito/default/RP_ORIGIN" when group=""', () => {
    const parameters = new Parameters(stack, 'Parameters', {
      group: '',
    });
    expect(parameters.rpOriginParameterPath).toBe('/passquito/default/RP_ORIGIN');
  });
});
