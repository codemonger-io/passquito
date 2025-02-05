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
import { composeMappingTemplate } from 'mapping-template-compose';

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

    // Lambda functions
    this.registrationLambda = new RustFunction(this, 'RegistrationLambda', {
      manifestPath,
      binaryName: 'registration',
      architecture: lambda.Architecture.ARM_64,
      environment: {
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
      'cognito-idp:AdminDeleteUser',
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

    // REST API
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

    // suppresses CORS errors caused when the gateway responds with errors
    // before reaching the integrations
    this.credentialsApi.addGatewayResponse('Unauthorized', {
      type: apigw.ResponseType.DEFAULT_4XX,
      responseHeaders: {
        'Access-Control-Allow-Origin': "'*'",
      },
    });
    this.credentialsApi.addGatewayResponse('InternalServerError', {
      type: apigw.ResponseType.DEFAULT_5XX,
      responseHeaders: {
        'Access-Control-Allow-Origin': "'*'",
      },
    });

    // defines models
    // - new user information
    const newUserInfoModel = this.credentialsApi.addModel('NewUserInfoModel', {
      description: 'New user information',
      contentType: 'application/json',
      schema: {
        schema: apigw.JsonSchemaVersion.DRAFT4,
        title: 'newUserInfo',
        description: 'New user information',
        type: apigw.JsonSchemaType.OBJECT,
        properties: {
          username: {
            description: 'Username. This is not necessary to be unique.',
            type: apigw.JsonSchemaType.STRING,
            example: 'monaka',
          },
          displayName: {
            description: 'Display name.',
            type: apigw.JsonSchemaType.STRING,
            example: 'Emoto, Monaka',
          },
        },
        required: ['username', 'displayName'],
      },
    });
    // - start registration session
    const startRegistrationSessionModel = this.credentialsApi.addModel(
      'StartRegistrationSessionModel',
      {
        description: 'Credential creation options associated with a registration session.',
        contentType: 'application/json',
        schema: {
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'startRegistrationSession',
          description: 'Credential creation options associated with a registration session.',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            sessionId: {
              description: 'Registration session ID.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
            credentialCreationOptions: {
              description: 'Credential creation options. See https://www.w3.org/TR/webauthn-3/#sctn-credentialcreationoptions-extension',
              type: apigw.JsonSchemaType.OBJECT,
              // TODO: add the schema
            },
          },
          required: ['sessionId', 'credentialCreationOptions'],
        },
      },
    );
    // - finish registration session
    const finishRegistrationSessionModel = this.credentialsApi.addModel(
      'FinishRegistrationSessionModel',
      {
        description: 'Public key credential for registration associated with a registration session.',
        contentType: 'application/json',
        schema: {
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'finishRegistrationSession',
          description: 'Public key credential for registration associated with a registration session.',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            sessionId: {
              description: 'Registration session ID.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
            publicKeyCredential: {
              description: 'Public key credential for registration. See https://www.w3.org/TR/webauthn-3/#iface-pkcredential',
              type: apigw.JsonSchemaType.OBJECT,
              // TODO: add the schema
            },
          },
        },
      },
    );

    // user pool authorizer
    const authorizer = augmentAuthorizer(
      new apigw.CognitoUserPoolsAuthorizer(this, 'UserPoolAuthorizer', {
        cognitoUserPools: [props.userPool.userPool],
      }),
      {
        description: 'Authorizer that authenticates users by ID tokens issued by the Cognito user pool.',
        type: 'apiKey',
        in: 'header',
        name: 'Authorization',
      },
    );

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
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['start', '$input.json("$")'],
          ]),
        },
        integrationResponses: makeIntegrationResponsesAllowCors([
          {
            statusCode: '400',
            selectionPattern: makeSelectionPattern('BadRequest'),
          },
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
        description: 'Start a registration session for a new user.',
        requestModels: {
          'application/json': newUserInfoModel,
        },
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Registration session has been successfully started.',
            responseModels: {
              'application/json': startRegistrationSessionModel,
            },
          },
          {
            statusCode: '400',
            description: 'Request payload is invalid.',
          },
          {
            statusCode: '503',
            description: 'Service is temporarily unavailable. Try again later.',
          },
        ]),
      },
    );
    // /registration/finish
    const registrationFinish = registration.addResource('finish');
    // - POST
    registrationFinish.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.registrationLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['finish', '$input.json("$")'],
          ]),
        },
        integrationResponses: makeIntegrationResponsesAllowCors([
          {
            statusCode: '400',
            selectionPattern: makeSelectionPattern('BadRequest'),
          },
          {
            statusCode: '401',
            selectionPattern: makeSelectionPattern('Unauthorized'),
          },
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
        description: 'Finish a registration session for a user. The public key credential of the user is verified and stored.',
        requestModels: {
          'application/json': finishRegistrationSessionModel,
        },
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Registration has been successfully finished.',
            // empty response
          },
          {
            statusCode: '400',
            description: 'Request payload is invalid.',
          },
          {
            statusCode: '401',
            description: 'Registration session is invalid or expired.',
          },
          {
            statusCode: '503',
            description: 'Service is temporarily unavailable. Try again later.',
          },
        ]),
      },
    );
    // /registration/invite
    const registrationInvite = registration.addResource('invite');
    // - POST
    registrationInvite.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.registrationLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['invite', composeMappingTemplate([
              ['cognitoSub', `"$util.escapeJavaScript($context.authorizer.claims.sub).replaceAll("\\'", "'")"`],
              ['userId', `"$util.escapeJavaScript($context.authorizer.claims["cognito:username"]).replaceAll("\\'", "'")"`],
            ])],
          ]),
        },
        integrationResponses: makeIntegrationResponsesAllowCors([
          {
            // BadRequest should not happen,
            // because this endpoint does not accept any user input
            statusCode: '500',
            selectionPattern: makeSelectionPattern('BadRequest'),
            reseponseTemplates: {
              'application/json': `{
                "errorType": "InternalServerError",
                "errorMessage": "internal error"
              }`
            },
          },
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        description: 'Generate an invitation URL for the user to register a new credential on a new device',
        authorizer,
        authorizationType: apigw.AuthorizationType.COGNITO,
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Invitation URL has been successfully generated.',
            // TODO: response model
          },
          {
            statusCode: '500',
            description: 'Internal server error',
          },
        ]),
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
        // no request model (shoud be empty but ignored)
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Discoverable credentials session has been successfully started.',
          },
          {
            statusCode: '503',
            description: 'Service is temporarily unavailable. Try again later.',
          },
        ]),
      },
    );

    // secured endpoints
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
