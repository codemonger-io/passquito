## API Report File for "@codemonger-io/passquito-cdk-construct"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts

import { aws_cognito } from 'aws-cdk-lib';
import { aws_dynamodb } from 'aws-cdk-lib';
import { aws_lambda } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { GhostStringParameter } from 'cdk-ghost-string-parameter';
import { RestApiWithSpec } from 'cdk-rest-api-with-spec';

// @beta
export class CredentialsApi extends Construct {
    constructor(scope: Construct, id: string, props: CredentialsApiProps);
    get basePath(): string;
    readonly cognitoFacadeLambda: aws_lambda.IFunction;
    readonly credentialsApi: RestApiWithSpec;
    readonly discoverableLambda: aws_lambda.IFunction;
    get internalUrl(): string;
    // (undocumented)
    readonly props: CredentialsApiProps;
    readonly registrationLambda: aws_lambda.IFunction;
    readonly securedLambda: aws_lambda.IFunction;
}

// @beta
export interface CredentialsApiProps {
    readonly allowOrigins: string[];
    readonly basePath: string;
    // Warning: (ae-forgotten-export) The symbol "Parameters_2" needs to be exported by the entry point index.d.ts
    readonly parameters: Parameters_2;
    // Warning: (ae-forgotten-export) The symbol "SessionStore" needs to be exported by the entry point index.d.ts
    readonly sessionStore: SessionStore;
    // Warning: (ae-forgotten-export) The symbol "UserPool" needs to be exported by the entry point index.d.ts
    readonly userPool: UserPool;
}

// @beta
export class PassquitoCore extends Construct {
    constructor(scope: Construct, id: string, props?: PassquitoCoreProps);
    readonly credentialsApi: CredentialsApi;
    get credentialsApiInternalUrl(): string;
    readonly parameters: Parameters_2;
    get rpOriginParameterPath(): string;
    readonly sessionStore: SessionStore;
    readonly userPool: UserPool;
    get userPoolClientId(): string;
    get userPoolId(): string;
}

// @beta
export interface PassquitoCoreProps {
    readonly distributionDomainName?: string;
}

```
