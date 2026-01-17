import * as path from 'node:path';
import {
  Duration,
  aws_apigateway as apigw,
  aws_cognito as cognito,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import { RustFunction } from 'cargo-lambda-cdk';
import { Construct } from 'constructs';

/**
 * Properties for {@link SecuredApi}.
 *
 * @beta
 */
export interface SecuredApiProps {
  /** Base path to deliver secured endpoints. */
  readonly basePath: string;

  /** Cognito user pool to secure the API. */
  readonly userPool: cognito.IUserPool;
}

/**
 * Provides API endpoints secured by a Cognito user pool.
 *
 * @beta
 */
export class SecuredApi extends Construct {
  /** Secured REST API. */
  readonly securedApi: apigw.RestApi;

  /** Lambda function that serves secured contents. */
  private readonly testEndpointLambda: lambda.IFunction;

  constructor(scope: Construct, id: string, readonly props: SecuredApiProps) {
    super(scope, id);

    const { basePath, userPool } = props;

    const testEndpointPath = `${basePath.replace(/\/$/, '')}/test`;

    this.testEndpointLambda = new RustFunction(this, 'TestEndpointLambda', {
      manifestPath: path.join(__dirname, '..', 'lambda', 'secured', 'Cargo.toml'),
      binaryName: 'test_endpoint',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        ENDPOINT_PATH: testEndpointPath,
      },
      memorySize: 128,
      timeout: Duration.seconds(5),
    });

    this.securedApi = new apigw.RestApi(this, 'SecuredApi', {
      description: 'API secured by Passquito user pool',
      defaultCorsPreflightOptions: {
        allowHeaders: ['Authorization', 'Content-Type'],
        allowMethods: apigw.Cors.ALL_METHODS,
        allowOrigins: ["*"],
        maxAge: Duration.days(1),
      },
      deploy: true,
      deployOptions: {
        description: 'Default deployment',
        stageName: 'default',
        loggingLevel: apigw.MethodLoggingLevel.INFO,
        throttlingRateLimit: 100,
        throttlingBurstLimit: 100,
        tracingEnabled: true,
      },
    });

    // user pool authorizer
    const authorizer = new apigw.CognitoUserPoolsAuthorizer(this, 'UserPoolAuthorizer', {
      cognitoUserPools: [userPool],
    });

    // gets to the base path
    const root = basePath
      .split('/')
      .filter((p) => p.length > 0)
      .reduce(
        (resource, part) => resource.addResource(part),
        this.securedApi.root,
      );

    // /test
    const testEndpoint = root.addResource('test');
    // - GET
    testEndpoint.addMethod(
      'GET',
      new apigw.LambdaIntegration(this.testEndpointLambda, {
        proxy: true,
        integrationResponses: [],
      }),
      {
        authorizer,
        authorizationType: apigw.AuthorizationType.COGNITO,
        methodResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': true,
              'method.response.header.Access-Control-Allow-Headers': true,
              'method.response.header.Access-Control-Allow-Methods': true,
            },
          },
        ],
      },
    );
  }

  get internalUrl(): string {
    return this.securedApi.deploymentStage.urlForPath(this.props.basePath);
  }
}
