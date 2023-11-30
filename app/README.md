# app

## Configuring authentication

You have to create `src/auth-config.ts` containing the configuration for authentication, which is never pushed to this repository.
You can find an example at [`src/auth-config.example.ts`](./src/auth-config.example.ts).

## Deploying the app

1. Deploy the CDK stack. See [`cdk/README.md`](../cdk/README.md).

2. Obtain the name of the S3 bucket for the app contents:

    ```sh
    APP_CONTENTS_BUCKET_NAME=`aws cloudformation describe-stacks --stack-name passkey-test --query "Stacks[0].Outputs[?OutputKey=='AppContentsBucketName'].OutputValue" --output text`
    ```

3. Build the app:

    ```sh
    pnpm build
    ```

4. Upload the app contents to the S3 bucket:

    ```sh
    aws s3 sync dist/ s3://$APP_CONTENTS_BUCKET_NAME/app/
    ```

## Recommended IDE Setup

[VSCode](https://code.visualstudio.com/) + [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) (and disable Vetur) + [TypeScript Vue Plugin (Volar)](https://marketplace.visualstudio.com/items?itemName=Vue.vscode-typescript-vue-plugin).

## Type Support for `.vue` Imports in TS

TypeScript cannot handle type information for `.vue` imports by default, so we replace the `tsc` CLI with `vue-tsc` for type checking. In editors, we need [TypeScript Vue Plugin (Volar)](https://marketplace.visualstudio.com/items?itemName=Vue.vscode-typescript-vue-plugin) to make the TypeScript language service aware of `.vue` types.

If the standalone TypeScript plugin doesn't feel fast enough to you, Volar has also implemented a [Take Over Mode](https://github.com/johnsoncodehk/volar/discussions/471#discussioncomment-1361669) that is more performant. You can enable it by the following steps:

1. Disable the built-in TypeScript Extension
    1) Run `Extensions: Show Built-in Extensions` from VSCode's command palette
    2) Find `TypeScript and JavaScript Language Features`, right click and select `Disable (Workspace)`
2. Reload the VSCode window by running `Developer: Reload Window` from the command palette.

## Customize configuration

See [Vite Configuration Reference](https://vitejs.dev/config/).

## Project Setup

```sh
pnpm install
```

### Compile and Hot-Reload for Development

```sh
pnpm dev
```

### Type-Check, Compile and Minify for Production

```sh
pnpm build
```

### Run Unit Tests with [Vitest](https://vitest.dev/)

```sh
pnpm test:unit
```

### Lint with [ESLint](https://eslint.org/)

```sh
pnpm lint
```
