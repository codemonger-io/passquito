# @codemonger-io/passquito-cdk-construct

[CDK Construct](https://docs.aws.amazon.com/cdk/v2/guide/constructs.html) for Passquito core resources.

## Getting started

### Installing the package

TBD: `@codemonger-io/passquito-cdk-construct` is not available on npm yet.

### Example

The `PassquitoCore` construct defines the core resources for Passquito.

```ts
import { Stack } from 'aws-cdk-lib';
import type { Construct } from 'constructs';

import { PassquitoCore } from '@codemonger-io/passquito-cdk-construct';

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const passquito = new PassquitoCore(this, 'Passquito');
  }
}
```

### Configuring relying party

You have to configure the origin URL of the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-3/#webauthn-relying-party) in the following parameter in [Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html):
- `/passkey-test/RP_ORIGIN`

### API documentation

You can find the [API documentation](./api/markdown/index.md) in the [`api/markdown`](./api/markdown/) folder, which is generated from the source code using [API Extractor](https://api-extractor.com).

## Passquito core resources

### User pool

A [Cognito user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools.html) that manages users.
Custom Lambda triggers are configured to deal with Passkey authentication.

### Credential table

A [DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html) table that stores public key credentials.
Public key credentials are associated with [user pool](#user-pool) users.

### Credentials API

An API Gateway REST API that provides endpoints for registration and authentication.
The authentication endpoints wrap the Cognito API calls.
Endpoints are implemented as [Lambda](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html) functions.

### Session table

A DynamoDB table that stores session information.
There are two kinds of sessions:
- registration session: used to register a new credential
- discoverable session: used to conduct authentication with a discoverable credential (passkey)

## Development

### Prerequisites

- [Node.js](https://nodejs.org/en) v18 or later. I have been using v22 for development.
- [pnpm](https://pnpm.io). This project uses pnpm as the package manager.

### Building the package

The `build` script removes the `dist` folder and builds the main JavaScript and type definition files in a brand-new `dist` folder.

```sh
pnpm build
```

If you want to incrementally update the `dist` folder during development, you can run the `build:noclean` script instead:

```sh
pnpm build:noclean
```

The `build` and `build:noclean` scripts run the following scripts:

- `build:js`: transpiles TypeScript files and bundles the outputs into a single JavaScript file
- `build:dts`: generates type definition (`.d.ts`) files and bundles them into a single file

### Lambda functions

You can find the source code of the Lambda functions in the [`lambda/authentication`](./lambda/authentication/) folder.
It is written in [Rust](https://www.rust-lang.org).
The contents of the `lambda/authentication` folder are copied to the `dist/lambda/authentication` folder and bundled into the package.