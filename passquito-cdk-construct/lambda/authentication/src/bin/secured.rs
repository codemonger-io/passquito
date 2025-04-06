//! Secured contents.
//!
//! This application is intended to run as an AWS Lambda function.
//!
//! You have to configure the following environment variable:
//! - `BASE_PATH`: base path to provide the service
//!
//! ## Endpoint
//!
//! Provides the following endpoint under the base path.
//!
//! ### `GET ${BASE_PATH}`
//!
//! Returns the following JSON object.
//!
//! ```json
//! {
//!   "message": "You are allowed to see this!"
//! }
//! ```

use lambda_http::{
    Body,
    Error,
    Request,
    RequestExt as _,
    Response,
    run,
    service_fn,
};
use std::env;
use std::sync::Arc;
use tracing::error;

use authentication::error_response::ErrorResponse;

struct SharedState {
    base_path: String,
}

impl SharedState {
    fn new() -> Result<Self, Error> {
        let base_path = env::var("BASE_PATH")
            .or(Err("BASE_PATH env must be set"))?;
        Ok(Self { base_path })
    }
}

const SECRET_MESSAGE: &str = r#"{"message": "You are allowed to see this!"}"#;

async fn function_handler(
    shared_state: Arc<SharedState>,
    event: Request,
) -> Result<Response<Body>, Error> {
    if event.raw_http_path() == shared_state.base_path {
        Ok(Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            // proxy integration needs this
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from(SECRET_MESSAGE))
            .expect("failed to render response"))
    } else {
        error!("unsupported path: {}", event.raw_http_path());
        ErrorResponse::bad_request("bad request").try_into()
    }
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

    let shared_state = Arc::new(SharedState::new()?);
    run(service_fn(|req| async {
        function_handler(shared_state.clone(), req).await
    })).await
}
