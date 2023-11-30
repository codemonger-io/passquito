# rp-server

Relying party server.

You can test passkeys on localhost.

1. Build the app:

    ```sh
    cd ../app
    pnpm build
    cd ../rp-server
    ```

2. Start the server:

    ```sh
    cargo run
    ```

   To see logs:

    ```sh
    RUST_LOG=trace cargo run
    ```

3. Open <http://localhost:3000/app/> on your browser.