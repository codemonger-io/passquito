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
} from '@codemonger-io/cdk-cors-utils';
import { RestApiWithSpec, augmentAuthorizer } from '@codemonger-io/cdk-rest-api-with-spec';
import { Construct } from 'constructs';
import { composeMappingTemplate } from '@codemonger-io/mapping-template-compose';

import type { SsmParameters } from './ssm-parameters';
import type { SessionStore } from './session-store';
import type { UserPool } from './user-pool';

/**
 * Props for {@link CredentialsApi}.
 *
 * @beta
 */
export interface CredentialsApiProps {
  /**
   * Base path where the API is to be served.
   *
   * @remarks
   *
   * Empty string means root, i.e., "/".
   */
  readonly basePath: string;

  /** Parameters in Parameter Store on AWS Systems Manager. */
  readonly ssmParameters: SsmParameters;

  /** Session store. */
  readonly sessionStore: SessionStore;

  /** User pool. */
  readonly userPool: UserPool;

  /**
   * Origins allowed to access the API.
   *
   * @remarks
   *
   * No CORS preflight is performed if empty.
   */
  readonly allowOrigins: string[];
}

/**
 * CDK construct that provisions the Credentials API.
 *
 * @beta
 */
export class CredentialsApi extends Construct {
  /** Lambda function for registration. */
  readonly registrationLambda: lambda.IFunction;

  /** Lambda function for discoverable credentials. */
  readonly discoverableLambda: lambda.IFunction;

  /** Lambda function for the facade that masks Cognito APIs. */
  readonly cognitoFacadeLambda: lambda.IFunction;

  /** Credentials API. */
  readonly credentialsApi: RestApiWithSpec;

  /**
   * Normalized base path.
   *
   * @remarks
   *
   * Surrounding whitespace is trimmed.
   * Leading slashes are reduced to a single slash, and trailing slashes are
   * removed. If there is no leading slash, one is added. It will be an empty
   * string if the base path is root, i.e., "/".
   */
  readonly normalizedBasePath: string;

  constructor(scope: Construct, id: string, props: CredentialsApiProps) {
    super(scope, id);

    const {
      allowOrigins,
      basePath,
      ssmParameters,
      sessionStore,
      userPool,
    } = props;
    const manifestPath = path.join(__dirname, 'lambda', 'authentication', 'Cargo.toml');
    this.normalizedBasePath = basePath
      .trim()
      .replace(/^\/*/, '/')
      .replace(/\/+$/, '');
    const securedBasePath = `${this.normalizedBasePath}/secured`;

    // Lambda functions
    this.registrationLambda = new RustFunction(this, 'RegistrationLambda', {
      description: 'Implements the endpoints to start and finish a registration session',
      manifestPath,
      binaryName: 'registration',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        SESSION_TABLE_NAME: sessionStore.sessionTable.tableName,
        USER_POOL_ID: userPool.userPoolId,
        CREDENTIAL_TABLE_NAME: userPool.credentialTableName,
        RP_ORIGIN_PARAMETER_PATH: ssmParameters.rpOriginParameter.parameterName,
      },
      memorySize: 128,
      timeout: Duration.seconds(5),
    });
    ssmParameters.rpOriginParameter.grantRead(this.registrationLambda);
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
      description: 'Implements the endpoint to start an authentication session with discoverable credentials',
      manifestPath,
      binaryName: 'discoverable',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        SESSION_TABLE_NAME: sessionStore.sessionTable.tableName,
        RP_ORIGIN_PARAMETER_PATH: ssmParameters.rpOriginParameter.parameterName,
      },
      memorySize: 128,
      timeout: Duration.seconds(5),
    });
    ssmParameters.rpOriginParameter.grantRead(this.discoverableLambda);
    sessionStore.sessionTable.grantReadWriteData(this.discoverableLambda);

    this.cognitoFacadeLambda = new RustFunction(this, 'CognitoFacadeLambda', {
      description: 'Wraps Cognito APIs to perform authentication and token refreshing',
      manifestPath,
      binaryName: 'cognito-facade',
      architecture: lambda.Architecture.ARM_64,
      environment: {
        USER_POOL_CLIENT_ID: userPool.userPoolClientId,
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
      defaultCorsPreflightOptions: allowOrigins.length > 0 ? {
        allowHeaders: ['Authorization', 'Content-Type'],
        allowMethods: ['GET', 'POST'],
        allowOrigins,
        maxAge: Duration.days(1),
      } : undefined,
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
    if (allowOrigins.length > 0) {
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
    }

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
          required: ['sessionId', 'publicKeyCredential'],
        },
      },
    );
    // - registration result
    const registrationResultModel = this.credentialsApi.addModel(
      'RegistrationResultModel',
      {
        description: 'Registration result.',
        contentType: 'application/json',
        schema: {
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'registrationResult',
          description: 'Registration result.',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            userId: {
              description: 'Unique user ID of the registered user.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
          },
          required: ['userId'],
        },
      },
    );
    // - WebAuthn extension of credentials request options
    //   https://www.w3.org/TR/webauthn-3/#sctn-credentialrequestoptions-extension
    const credentialRequestOptionsModel = this.credentialsApi.addModel(
      'CredentialRequestOptionsModel',
      {
        description: 'WebAuthn extension of credentials request options.',
        contentType: 'application/json',
        schema: {
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'credentialRequestOptions',
          description: 'WebAuthn extension of credentials request options.',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            publicKey: {
              description: 'Credential request options for a public key. See https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions for more details.',
              type: apigw.JsonSchemaType.OBJECT,
            },
            mediation: {
              description: 'Mediation requirements for the credential request.',
              type: apigw.JsonSchemaType.STRING,
            },
          },
          required: ['publicKey'],
        },
      },
    );
    // - user ID
    const userIdModel = this.credentialsApi.addModel(
      'UserIdModel',
      {
        description: 'User ID for authentication.',
        contentType: 'application/json',
        schema: {
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'userId',
          description: 'User ID for authentication.',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            userId: {
              description: 'Unique user ID issued by Passquito.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
          },
          required: ['userId'],
        },
      },
    );
    // - authentication session
    const authenticationSessionModel = this.credentialsApi.addModel(
      'AuthenticationSessionModel',
      {
        description: 'Authentication session.',
        contentType: 'application/json',
        schema: {
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'authenticationSession',
          description: 'Authentication session.',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            sessionId: {
              description: 'Session ID. Pass this to the finish endpoint.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
            credentialRequestOptions: {
              modelRef: credentialRequestOptionsModel,
            },
          },
          required: ['session', 'credentialRequestOptions'],
        },
      },
    );
    // - authentication session to finish
    const finishAuthenticationSessionModel = this.credentialsApi.addModel(
      'FinishAuthenticationSessionModel',
      {
        description: 'Public key credential for authentication responding to an authentication session.',
        contentType: 'application/json',
        schema: {
          description: 'Public key credential for authentication responding to an authentication session.',
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'finishAuthenticationSession',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            sessionId: {
              description: 'Session ID to finish, which has been issued by the start endpoint.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
            userId: {
              description: 'ID of the user to be authenticated.',
              type: apigw.JsonSchemaType.STRING,
              example: '0123456789abcdef',
            },
            publicKey: {
              description: 'Public key credential for authentication. See https://www.w3.org/TR/webauthn-3/#iface-pkcredential for more details',
              type: apigw.JsonSchemaType.OBJECT,
            },
          },
          required: ['session', 'userId', 'publicKey'],
        },
      },
    );
    // - authentication result
    const authenticationResultModel = this.credentialsApi.addModel(
      'AuthenticationResultModel',
      {
        description: 'Authentication result.',
        contentType: 'application/json',
        schema: {
          description: 'Authentication result.',
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'authenticationResult',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            accessToken: {
              description: 'Access token issued by the Cognito user pool client.',
              type: apigw.JsonSchemaType.STRING,
            },
            idToken: {
              description: 'ID token issued by the Cognito user pool. Use this token to access secured endpoints of the Passquito API.',
              type: apigw.JsonSchemaType.STRING,
            },
            refreshToken: {
              description: 'Refresh token issued by the Cognito user pool.',
              type: apigw.JsonSchemaType.STRING,
            },
            expiresIn: {
              description: 'Expiration time of the access and ID tokens in seconds.',
              type: apigw.JsonSchemaType.INTEGER,
              example: 3600,
            },
          },
          required: ['accessToken', 'expiresIn', 'idToken', 'refreshToken'],
        },
      },
    );
    // - refresh token
    const refreshTokenModel = this.credentialsApi.addModel(
      'RefreshTokenModel',
      {
        description: 'Refresh token.',
        contentType: 'application/json',
        schema: {
          description: 'Refresh token.',
          schema: apigw.JsonSchemaVersion.DRAFT4,
          title: 'refreshToken',
          type: apigw.JsonSchemaType.OBJECT,
          properties: {
            refreshToken: {
              description: 'Refresh token issued by the Cognito user pool.',
              type: apigw.JsonSchemaType.STRING,
            },
          },
          required: ['refreshToken'],
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

    // common 5xx response
    const common5xxResponses = {
      integrationResponses: [
        {
          statusCode: '503',
          selectionPattern: makeSelectionPattern('ServiceUnavailable'),
        } as const,
        {
          statusCode: '500',
          selectionPattern: makeSelectionPattern('(BadConfiguration|Unhandled)'),
        } as const,
      ] as const,
      methodResponses: [
        {
          statusCode: '503',
          description: 'Service is temporarily unavailable. Try again later.',
        } as const,
        {
          statusCode: '500',
          description: 'Internal server error. Maybe due to misconfiguration.',
        } as const,
      ] as const,
    } as const;

    // gets to the base path
    const root = this.normalizedBasePath
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
          ...common5xxResponses.integrationResponses,
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
          ...common5xxResponses.methodResponses,
        ]),
      },
    );
    // /registration/start-verified
    const registrationStartVerified = registration.addResource('start-verified');
    // - POST
    registrationStartVerified.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.registrationLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['startVerified', composeMappingTemplate([
              ['username', '$input.json("$.username")'],
              ['displayName', '$input.json("$.displayName")'],
              ['cognitoSub', `"$util.escapeJavaScript($context.authorizer.claims.sub).replaceAll("\\'", "'")"`],
              ['userId', `"$util.escapeJavaScript($context.authorizer.claims["cognito:username"]).replaceAll("\\'", "'")"`],
            ])],
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
          ...common5xxResponses.integrationResponses,
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        description: 'Start a registration session for a verified user.',
        authorizer,
        authorizationType: apigw.AuthorizationType.COGNITO,
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
            statusCode: '401',
            description: 'User is not allowed to start registration as a verified user.',
          },
          ...common5xxResponses.methodResponses,
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
          ...common5xxResponses.integrationResponses,
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
            responseModels: {
              'application/json': registrationResultModel,
            },
          },
          {
            statusCode: '400',
            description: 'Request payload is invalid.',
          },
          {
            statusCode: '401',
            description: 'Registration session is invalid or expired.',
          },
          ...common5xxResponses.methodResponses,
        ]),
      },
    );

    // authentication endpoints
    const authentication = root.addResource('authentication');
    // /authentication/discover
    const authenticationDiscover = authentication.addResource('discover');
    // - POST
    authenticationDiscover.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.discoverableLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': '{}',
        },
        integrationResponses: makeIntegrationResponsesAllowCors([
          ...common5xxResponses.integrationResponses,
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        description: 'Start an authentication session with a discoverable credential (passkey).',
        // no request model (shoud be empty but ignored)
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Discoverable credentials session has been successfully started.',
            responseModels: {
              'application/json': credentialRequestOptionsModel,
            },
          },
          ...common5xxResponses.methodResponses,
        ]),
      },
    );
    // the following endpoints serve as the facade that masks Cognito APIs
    // /authentication/start
    const authenticationStart = authentication.addResource('start');
    // - POST
    authenticationStart.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.cognitoFacadeLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['start', composeMappingTemplate([
              ['userId', '$input.json("$.userId")'],
            ])],
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
          ...common5xxResponses.integrationResponses,
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        description: 'Start an authentication session.',
        requestModels: {
          'application/json': userIdModel,
        },
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Successfully initiated the authentication session.',
            responseModels: {
              'application/json': authenticationSessionModel,
            },
          },
          {
            statusCode: '400',
            description: 'Request payload is invalid.',
          },
          {
            statusCode: '401',
            description: 'The user is not allowed to start authentication.',
          },
          ...common5xxResponses.methodResponses,
        ]),
      },
    );
    // /authentication/finish
    const authenticationFinish = authentication.addResource('finish');
    // POST
    authenticationFinish.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.cognitoFacadeLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['finish', composeMappingTemplate([
              ['sessionId', '$input.json("$.sessionId")'],
              ['userId', '$input.json("$.userId")'],
              ['publicKey', '$input.json("$.publicKey")'],
            ])]
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
          ...common5xxResponses.integrationResponses,
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        description: 'Finish an authentication session.',
        requestModels: {
          'application/json': finishAuthenticationSessionModel,
        },
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Successfully finished the authentication session.',
            responseModels: {
              'application/json': authenticationResultModel,
            },
          },
          {
            statusCode: '400',
            description: 'Request payload is invalid.',
          },
          {
            statusCode: '401',
            description: 'Failed to authenticate the user.',
          },
          ...common5xxResponses.methodResponses,
        ]),
      },
    );
    // /authentication/refresh
    const authenticationRefresh = authentication.addResource('refresh');
    // - POST
    authenticationRefresh.addMethod(
      'POST',
      new apigw.LambdaIntegration(this.cognitoFacadeLambda, {
        proxy: false,
        passthroughBehavior: apigw.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': composeMappingTemplate([
            ['refresh', composeMappingTemplate([
              ['refreshToken', '$input.json("$.refreshToken")'],
            ])]
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
          ...common5xxResponses.integrationResponses,
          {
            statusCode: '200',
          },
        ]),
      }),
      {
        description: 'Refresh the ID and access tokens with the refresh token.',
        requestModels: {
          'application/json': refreshTokenModel,
        },
        methodResponses: makeMethodResponsesAllowCors([
          {
            statusCode: '200',
            description: 'Successfully refreshed the tokens.',
            responseModels: {
              'application/json': authenticationResultModel,
            },
          },
          {
            statusCode: '400',
            description: 'Request payload is invalid.',
          },
          {
            statusCode: '401',
            description: 'Failed to refresh the tokens. Refresh token is likely invalid.',
          },
          ...common5xxResponses.methodResponses,
        ]),
      },
    );
  }

  /**
   * Base path of the Credentials API not including the trailing slash except
   * for root.
   */
  get basePath(): string {
    return this.normalizedBasePath || '/';
  }

  /** Internal URL of the Credentials API. */
  get internalUrl(): string {
    return this.credentialsApi.deploymentStage.urlForPath(this.basePath);
  }
}

// Makes a selection pattern for a given erro type.
function makeSelectionPattern(errorType: string): string {
  // NOTE: "." may not match line endings
  return `^\\[${errorType}\\](\\n|.)+`;
}
