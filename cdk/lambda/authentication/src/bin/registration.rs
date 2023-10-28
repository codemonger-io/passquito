//! Registration.
//!
//! You have to configure the following environment variable:
//! - `BASE_PATH`: base path to provide the service; e.g., `/auth/cedentials/`.
//!
//! ## Endpoints
//!
//! Provides the following endpoints under the base path.
//!
//! ### `POST ${BASE_PATH}start`
//!
//! Starts registration of a new user.
//! The body must be [`NewUserInfo`] as `application/json`.
//!
//! ### `POST ${BASE_PATH}finish`
//!
//! Verifies the new user and finishes registration.

use lambda_http::{
    Body,
    Error,
    Request,
    RequestExt,
    RequestPayloadExt,
    Response,
    http::StatusCode,
    run,
    service_fn,
};
use serde::Deserialize;
use std::env;
use tracing::info;

/// Information on a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewUserInfo {
    /// Username.
    pub username: String,

    /// Display name.
    pub display_name: String,
}

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    let base_path = env::var("BASE_PATH")
        .or(Err("BASE_PATH env must be configured"))?;
    let base_path = base_path.trim_end_matches('/');
    let job_path = event.raw_http_path().strip_prefix(base_path)
        .ok_or(format!("path must start with \"{}\"", base_path))?;
    match job_path {
        "/start" => {
            let user_info: NewUserInfo = event
                .payload()?
                .ok_or("missing new user info")?;
            start_registration(user_info).await
        }
        _ => Err(format!("unsupported job path: {}", job_path).into()),
    }
}

async fn start_registration(user_info: NewUserInfo) -> Result<Response<Body>, Error> {
    info!("start_registration: {:?}", user_info);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body("Hello, world!".into())?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();
    run(service_fn(function_handler)).await
}