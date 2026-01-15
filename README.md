# Passquito

![Passquito](./passquito.png)

Fly with [Passkey](https://passkeys.dev) &times; [AWS Cognito](https://aws.amazon.com/cognito/) = Passquito!

A PoC on [passkey](https://passkeys.dev) authentication inspired by [`aws-samples/amazon-cognito-passwordless-auth`](https://github.com/aws-samples/amazon-cognito-passwordless-auth).

Features:
- [Rust](https://www.rust-lang.org) &times; [AWS Lambda](https://aws.amazon.com/lambda/) → Snappy cold start!
- [AWS Cognito](https://aws.amazon.com/cognito/) Lambda triggers
- &#x1F4A9; Ugly codebase

## Getting started

Passquito consists of two packages:
- [`@codemonger-io/passquito-cdk-construct`](./passquito-cdk-construct/) is a CDK construct which describes Passquito core resources on AWS.
- [`@codemonger-io/passquito-client-js`](./passquito-client-js/) is a JavaScript client library which facilitates the communication with Passquito core resources.

### Steps

1. Add `@codemonger-io/passquito-cdk-construct` to your CDK project (replace `0.0.6-abc1234` with the version you want to install):

    ```sh
    npm install @codemonger-io/passquito-cdk-construct@0.0.6-abc1234
    ```

   Note that `@codemonger-io/passquito-cdk-construct` is **only available from the GitHub npm registry** for now.
   Please refer to its [`README`](./passquito-cdk-construct/README.md#installing-the-package) for more details.

2. Add `@codemonger-io/passquito-client-js` to your web application (replace `0.0.3-abc1234` with the version you want to install):

    ```sh
    npm install @codemonger-io/passquito-client-js@0.0.3-abc1234
    ```

   Note that `@codemonger-io/passquito-client-js` is **only available from the GitHub npm registry** for now.
   Please refer to its [`README`](./passquito-client-js/README.md#installing-the-package) for more details.

3. Include `PassquitoCore` in your CDK stack:

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

4. Use `@codemonger-io/passquito-client-js` in your web application to communicate with Passquito core resources.
   Please refer to its [`README`](./passquito-client-js/README.md#usage-in-a-nutshell) for how to use it.

## Usage scenarios in a nutshell

Please refer to the [`README` of `@codemonger-io/passquito-client-js`](./passquito-client-js/README.md#usage-in-a-nutshell).

## Interactions under the hood

Please refer to [`interactions-under-the-hood.md`](./interactions-under-the-hood.md) for how your app, Passquito, and AWS Cognito interact with each other.

## License

[MIT License](./LICENSE)

Except for the following materials licensed under _CC BY-SA 4.0_ (<https://creativecommons.org/licenses/by-sa/4.0/>):
- [_Passquito Logo_](./passquito.png) by [codemonger](https://codemonger.io)