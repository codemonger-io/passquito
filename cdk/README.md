# Welcome to your CDK TypeScript project

This is a blank project for CDK development with TypeScript.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

## AWS_PROFILE

```sh
export AWS_PROFILE=kikuo-jp
```

## Bootstrapping

```sh
pnpm cdk bootstrap
```

## Checking types

```sh
pnpm type-check
```

## Synthesizing CloudFormation template

```sh
pnpm cdk synth
```

## Deploying

```sh
pnpm cdk deploy
```

The app distribution is not allowed CORS access to the credentials API at the first deployment because the domain name of the CloudFront distribution is unknown at that time.
You have to **deploy the stack twice to activate the CORS configuration**.

## Post-deployment configuration

### Origin URL of relying party

Use the CloudFront distribution URL.

```sh
pnpm tsx ./scripts/set-rp-origin
```

Use a specific URL.

```sh
pnpm tsx ./scripts/set-rp-origin http://localhost:5173
```

## CloudFormation outputs

### User pool ID

```sh
aws cloudformation describe-stacks --stack-name passkey-test --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text
```

### User pool client ID

```sh
aws cloudformation describe-stacks --stack-name passkey-test --query "Stacks[0].Outputs[?OutputKey=='UserPoolClientId'].OutputValue" --output text
```

### Credentials API URL for internal use

```sh
aws cloudformation describe-stacks --stack-name passkey-test --query "Stacks[0].Outputs[?OutputKey=='CredentialsApiInternalUrl'].OutputValue" --output text
```

### S3 bucket name for app contents

```sh
aws cloudformation describe-stacks --stack-name passkey-test --query "Stacks[0].Outputs[?OutputKey=='AppContentsBucketName'].OutputValue" --output text
```

### App URL

```sh
aws cloudformation describe-stacks --stack-name passkey-test --query "Stacks[0].Outputs[?OutputKey=='AppUrl'].OutputValue" --output text
```
id="request-custom-headers-behavior"
## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
