import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';
import esbuild from 'rollup-plugin-esbuild';

export default {
  input: 'src/index.ts',
  external: [
    /@aws-cdk/, // should be part of AWS CDK
    /@aws-sdk/,
    'aws-cdk-lib',
    'cargo-lambda-cdk',
    'cdk-rest-api-with-spec',
    'cdk-ghost-string-parameter',
    'cdk2-cors-utils',
    'constructs',
    'mapping-template-compose',
  ],
  output: {
    file: 'dist/passquito-cdk-construct.js',
    format: 'cjs',
  },
  plugins: [
    nodeResolve(),
    esbuild({
      minify: false,
      exclude: [
        /node_modules/,
      ],
    }),
    commonjs(), // bundles CommonJS dependencies
  ],
}
