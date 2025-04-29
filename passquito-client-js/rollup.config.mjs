import esbuild from 'rollup-plugin-esbuild';

export default {
  input: 'src/index.ts',
  external: [
    /@github\/webauthn-json/, // also matches submodules
  ],
  output: {
    file: 'dist/passquito-client-js.mjs',
    format: 'esm',
  },
  plugins: [
    esbuild({
      minify: false,
      exclude: [
        /node_modules/,
      ],
    }),
  ],
}
