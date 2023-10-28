import * as path from 'node:path';
import { CorsHttpMethod, HttpApi, HttpMethod } from '@aws-cdk/aws-apigatewayv2-alpha';
import { HttpLambdaIntegration } from '@aws-cdk/aws-apigatewayv2-integrations-alpha';
import { Duration, aws_lambda as lambda } from 'aws-cdk-lib';
import { RustFunction } from 'cargo-lambda-cdk';
import { Construct } from 'constructs';

import type { UserPool } from './user-pool';

/** Props for `CredentialsApi`. */
export interface CredentialsApiProps {
    /** Base path where tht API is to be served. */
    readonly basePath: string;

    /** User pool. */
    readonly userPool: UserPool;
}

/** CDK construct that provisions the Credentials API. */
export class CredentialsApi extends Construct {
    /** Lambda function for registration. */
    readonly registrationLambda: lambda.IFunction;

    /** Credentials API. */
    readonly credentialsApi: HttpApi;

    constructor(scope: Construct, id: string, readonly props: CredentialsApiProps) {
        super(scope, id);

        const { basePath, userPool } = props;
        const registrationBasePath = `${basePath.replace(/\/$/, '')}/registration/`;

        this.registrationLambda = new RustFunction(this, 'RegistrationLambda', {
            manifestPath: path.join('lambda', 'authentication', 'Cargo.toml'),
            binaryName: 'registration',
            architecture: lambda.Architecture.ARM_64,
            environment: {
                BASE_PATH: registrationBasePath,
            },
            memorySize: 128,
            timeout: Duration.seconds(5),
        });

        this.credentialsApi = new HttpApi(this, 'CredentialsApi', {
            description: 'API to manage credentials',
            createDefaultStage: true,
            corsPreflight: {
                allowHeaders: ['Content-Type'],
                allowMethods: [CorsHttpMethod.POST],
                allowOrigins: ['http://localhost:5173'],
                maxAge: Duration.days(1),
            },
        });
        this.credentialsApi.addRoutes({
            path: `${registrationBasePath}{proxy+}`,
            methods: [HttpMethod.POST],
            integration: new HttpLambdaIntegration('Registration', this.registrationLambda),
        });
    }

    /** Internal URL of the Credentials API. */
    get internalUrl(): string {
        return `${this.credentialsApi.defaultStage!.url}${this.props.basePath.replace(/^\//, '')}`;
    }
}