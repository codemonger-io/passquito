import * as path from 'node:path';
import {
  Duration,
  aws_apigateway as apigw,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import { RustFunction } from 'cargo-lambda-cdk';
import {
  makeIntegrationResponsesAllowCors,
  makeMethodResponsesAllowCors,
} from 'cdk2-cors-utils';
import { RestApiWithSpec, augmentAuthorizer } from 'cdk-rest-api-with-spec';
import { Construct } from 'constructs';

import type { Parameters } from './parameters';
import type { SessionStore } from './session-store';
import type { UserPool } from './user-pool';

/** Props for `CredentialsApi`. */
export interface CredentialsApiProps {
  /** Base path where tht API is to be served. */
  readonly basePath: string;

  /** Parameters in Parameter Store on AWS Systems Manager. */
  readonly parameters: Parameters;

  /** Session store. */
  readonly sessionStore: SessionStore;

  /** User pool. */
  readonly userPool: UserPool;

  /** Origins allowed to access the API. */
  readonly allowOrigins: string[];
}

/** CDK construct that provisions the Credentials API. */
export class CredentialsApi extends Construct {
  /** Lambda function for registration. */
  readonly registrationLambda: lambda.IFunction;

  /** Lambda function for discoverable credentials. */
  readonly discoverableLambda: lambda.IFunction;

  /** Lambda function that serves secured contents. */
  readonly securedLambda: lambda.IFunction;

  /** Credentials API. */
  readonly credentialsApi: RestApiWithSpec;

  constructor(scope: Construct, id: string, readonly props: CredentialsApiProps) {
    super(scope, id);

    const {
      allowOrigins,
      basePath,
      parameters,
      sessionStore,
      userPool,
    } = props;
    const manifestPath = path.join('lambda', 'authentication', 'Cargo.toml');
    const registrationBasePath = `${basePath.replace(/\/$/, '')}/registration/`;
    const discoverableBasePath = `${basePath.replace(/\/$/, '')}/discoverable/`;
    const securedBasePath = `${basePath.replace(/\/$/, '')}/secured`;

    this.registrationLambda = new RustFunction(this, 'RegistrationLambda', {
      manifestPath,
      binaryName: 'registration',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        BASE_PATH: registrationBasePath,
        SESSION_TABLE_NAME: sessionStore.sessionTable.tableName,
        USER_POOL_ID: userPool.userPool.userPoolId,
        CREDENTIAL_TABLE_NAME: userPool.credentialTable.tableName,
        RP_ORIGIN_PARAMETER_PATH: parameters.rpOriginParameter.parameterName,
      },
      memorySize: 128,
      timeout: Duration.seconds(5),
    });
    parameters.rpOriginParameter.grantRead(this.registrationLambda);
    sessionStore.sessionTable.grantReadWriteData(this.registrationLambda);
    userPool.credentialTable.grantReadWriteData(this.registrationLambda);
    userPool.userPool.grant(
      this.registrationLambda,
      'cognito-idp:AdminCreateUser',
      'cognito-idp:AdminSetUserPassword',
      'cognito-idp:ListUsers',
    );

    this.discoverableLambda = new RustFunction(this, 'DiscoverableLambda', {
      manifestPath,
      binaryName: 'discoverable',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        SESSION_TABLE_NAME: sessionStore.sessionTable.tableName,
        RP_ORIGIN_PARAMETER_PATH: parameters.rpOriginParameter.parameterName,
      },
      memorySize: 128,
      timeout: Duration.seconds(5),
    });
    parameters.rpOriginParameter.grantRead(this.discoverableLambda);
    sessionStore.sessionTable.grantReadWriteData(this.discoverableLambda);

    this.securedLambda = new RustFunction(this, 'SecuredLambda', {
      manifestPath,
      binaryName: 'secured',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        BASE_PATH: securedBasePath
      },
      memorySize: 128,
      timeout: Duration.seconds(5),
    });

    this.credentialsApi = new RestApiWithSpec(this, 'CredentialsRestApi', {
      description: 'API to manage credentials',
      openApiInfo: {
        version: '0.0.1',
      },
      openApiOutputPath: path.join('openapi', 'credentials-api.json'),
      defaultCorsPreflightOptions: {
        allowHeaders: ['Authorization', 'Content-Type'],
        allowMethods: ['GET', 'POST'],
        allowOrigins,
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

    // defines models
    const emptyModel = this.credentialsApi.addModel('EmptyModel', {
      description: 'Empty object',
      contentType: 'application/json',
      schema: {
        schema: apigw.JsonSchemaVersion.DRAFT4,
        title: 'emptyResponse',
        type: apigw.JsonSchemaType.OBJECT,
      },
    });

    // gets to the base path
    const root = props.basePath
      .split('/')
      .filter((p) => p.length > 0)
      .reduce(
        (resource, part) => resource.addResource(part),
        this.credentialsApi.root,
      );

    // registration endpoints
    const registration = root.addResource('registration');
    // /registration/start
    const registrationStart = registration.addResource('start');
    // - POST
    registrationStart.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.registrationLambda, {
        proxy: true,
        integrationResponses: makeIntegrationResponsesAllowCors([]),
      }),
      {
        methodResponses: makeMethodResponsesAllowCors([]),
      },
    );
    // /registration/finish
    const registrationFinish = registration.addResource('finish');
    // - POST
    registrationFinish.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.registrationLambda, {
        proxy: true,
        integrationResponses: makeIntegrationResponsesAllowCors([]),
      }),
      {
        methodResponses: makeMethodResponsesAllowCors([]),
      },
    );

    // discoverable endpoints
    const discoverable = root.addResource('discoverable');
    // /discoverable/start
    const discoverableStart = discoverable.addResource('start');
    // - POST
    discoverableStart.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.discoverableLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': '{}',
        },
        integrationResponses: makeIntegrationResponsesAllowCors([
          {
            statusCode: '503',
            selectionPattern: makeSelectionPattern('ServiceUnavailable'),
          },
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        requestModels: {
          'application/json': emptyModel,
        },
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Discoverable credentials session has been successfully started.',
          },
          {
            statusCode: '503',
            description: 'Service is not temporarily available. Try again later.',
          },
        ]),
      },
    );

    // secured endpoints
    const authorizer = augmentAuthorizer(
      new apigw.CognitoUserPoolsAuthorizer(this, 'UserPoolAuthorizer', {
        cognitoUserPools: [props.userPool.userPool],
      }),
      {
        type: 'apiKey',
        in: 'header',
        name: 'Authorization',
      },
    );
    const secured = root.addResource('secured');
    secured.addMethod(
      'GET',
      new apigw.LambdaIntegration(this.securedLambda, {
        proxy: true,
        integrationResponses: makeIntegrationResponsesAllowCors([]),
      }),
      {
        authorizer,
        authorizationType: apigw.AuthorizationType.COGNITO,
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
          },
        ]),
      },
    );
  }

  /** Base path of the Credentials API not including the trailing slash. */
  get basePath(): string {
    return this.props.basePath.replace(/\/$/, '');
  }

  /** Internal URL of the Credentials API. */
  get internalUrl(): string {
    return this.credentialsApi.deploymentStage.urlForPath(this.props.basePath);
  }
}

// Makes a selection pattern for a given erro type.
function makeSelectionPattern(errorType: string): string {
  // NOTE: "." may not match line endings
  return `^\\[${errorType}\\](\\n|.)+`;
}
