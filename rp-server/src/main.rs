//! Locally runs the server.
//!
//! You have to build the app before running this.

use axum::{
    BoxError,
    Extension,
    Router,
    error_handling::HandleErrorLayer,
    routing::{get, post},
};
use cookie::SameSite;
use http::StatusCode;
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::services::{ServeDir, ServeFile};
use tower_sessions::{MemoryStore, SessionManagerLayer};

use rp_server::auth::{
    finish_authentication_for_anyone,
    finish_register,
    start_authentication,
    start_authentication_for_anyone,
    start_register,
};
use rp_server::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app_state = AppState::new();

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(
            SessionManagerLayer::new(session_store)
                .with_name("webauthn")
                .with_same_site(SameSite::Lax)
                .with_secure(false), // TODO: → true in production
        );

    let auth_routes = Router::new()
        .route("/register-start", post(start_register))
        .route("/register-finish", post(finish_register))
        .route("/login-start", get(start_authentication_for_anyone))
        .route("/login-start", post(start_authentication))
        .route("/login-finish", post(finish_authentication_for_anyone));

    let app = Router::new()
        .route("/", get(root))
        .nest("/auth", auth_routes)
        .nest_service(
            "/app",
            ServeDir::new("../app/dist")
                .fallback(ServeFile::new("../app/dist/index.html")),
        )
        .layer(Extension(app_state))
        .layer(session_service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
}
