# @codemonger-io/passquito-cdk-construct

[CDK Construct](https://docs.aws.amazon.com/cdk/v2/guide/constructs.html) for Passquito core resources.

## Getting started

### Installing the package

`@codemonger-io/passquito-cdk-construct` is not available on npm yet.
Instead, _developer packages_ [^1] are available on the npm registry managed by GitHub Packages.
You can find packages [here](https://github.com/codemonger-io/passquito/pkgs/npm/passquito-cdk-construct).

[^1]: A _developer package_ is published to the GitHub npm registry, whenever commits are pushed to the `main` branch of this repository.
It has a special version number followed by a dash (`-`) plus a short commit hash; e.g., `0.0.4-abc1234` where `abc1234` is the short commit hash (the first 7 characters) of the commit used to build the package (_snapshot_).

#### Configuring a GitHub personal access token

To install a developer package, you need to configure a **classic** GitHub personal access token (PAT) with at least the `read:packages` scope.
Please refer to the [GitHub documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic) for how to create a PAT.

Once you have a PAT, create a `.npmrc` file in your home directory with the following content (please replace `$YOUR_GITHUB_PAT` with your actual PAT):

```
//npm.pkg.github.com/:_authToken=$YOUR_GITHUB_PAT
```

In the root directory of your project, create another `.npmrc` file with the following content:

```
@codemonger-io:registry=https://npm.pkg.github.com
```

Then you can install a _developer package_ with the following command:

```sh
npm install @codemonger-io/passquito-cdk-construct@0.0.4-abc1234
```

Please replace `0.0.4-abc1234` with the actual version number of the _snapshot_ you want to install, which is available in the [package repository](https://github.com/codemonger-io/passquito/pkgs/npm/passquito-cdk-construct).

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