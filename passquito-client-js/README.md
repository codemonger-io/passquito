# @codemonger-io/passquito-client-js

Passquito client for web applications.

## Getting started

### Installing the package

`@codemonger-io/passquito-client-js` is not available on npm yet.
Instead, _developer packages_ [^1] are available on the npm registry managed by GitHub Packages.
You can find packages [here](https://github.com/codemonger-io/passquito/pkgs/npm/passquito-client-js).

[^1]: A _developer package_ is published to the GitHub npm registry, whenever commits are pushed to the `main` branch of this repository.
It has a special version number followed by a dash (`-`) plus a short commit hash; e.g., `0.0.1-abc1234` where `abc1234` is the short commit hash (the first 7 characters) of the commit used to build the package (_snapshot_).

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
npm install @codemonger-io/passquito-client-js@0.0.1-abc1234
```

Please replace `0.0.1-abc1234` with the actual version number of the _snapshot_ you want to install, which is available in the [package repository](https://github.com/codemonger-io/passquito/pkgs/npm/passquito-client-js).

### API documentation

You can find the [API documentation](./api/markdown/index.md) in the [`api/markdown`](./api/markdown) folder, which is generated from the source code using [API Extractor](https://api-extractor.com).

## Development

### Prerequisites

- [Node.js](https://nodejs.org/en) v18 or later. I have been using v22 for development.
- [pnpm](https://pnpm.io). This project uses pnpm as the package manager.

### Building the package

The `build` script removes the `dist` folder and builds the main JavaScript and type definition files in a brand-new `dist` folder.

```sh
pnpm build
```

The `build` script runs the following scripts:

- `build:js`: transpiles TypeScript files and bundles the outputs into a single JavaScript file
- `build:dts`: generates type definition (`.d.ts`) files and bundles them into a single file