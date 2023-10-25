# Welcome to your CDK TypeScript project

This is a blank project for CDK development with TypeScript.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

## AWS_PROFILE

```sh
export AWS_PROFILE=kikuo-jp
```

## Bootstrapping

```sh
pnpm exec cdk bootstrap
```

## Synthesizing CloudFormation template

```sh
pnpm exec cdk synth
```

## Deploying

```sh
pnpm exec cdk deploy
```

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
