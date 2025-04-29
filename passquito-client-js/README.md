# @codemonger-io/passquito-client-js

Passquito client for web applications.

## Getting started

### Installing the package

TBD: `@codemonger-io/passquito-client-js` is not available on npm yet.

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