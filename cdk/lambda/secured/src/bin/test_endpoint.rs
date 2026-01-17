//! Secured contents.
//!
//! This application is intended to run as an AWS Lambda function.
//!
//! You have to configure the following environment variable:
//! - `ENDPOINT_PATH`: path from which this service is provided
//!
//! ## Endpoint
//!
//! Provides the following endpoint under the base path.
//!
//! ### `GET ${ENDPOINT_PATH}`
//!
//! Returns the following JSON object.
//!
//! ```json
//! {
//!   "message": "<User ID>, you are allowed to see this!"
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

struct SharedState {
    endpoint_path: String,
}

impl SharedState {
    fn new() -> Result<Self, Error> {
        let endpoint_path = env::var("ENDPOINT_PATH")
            .or(Err("ENDPOINT_PATH env must be set"))?;
        Ok(Self { endpoint_path })
    }
}

async fn function_handler(
    shared_state: Arc<SharedState>,
    event: Request,
) -> Result<Response<Body>, Error> {
    if event.raw_http_path() == shared_state.endpoint_path {
        if event.request_context().authorizer().is_none() {
            tracing::warn!("no authorizer present!");
        }
        let user_id = event
            .request_context()
            .authorizer()
            .and_then(|auth| {
                if let Some(jwt) = &auth.jwt {
                    tracing::info!("reading username from JWT");
                    let username = jwt.claims.get("cognito:username");
                    if username.is_none() {
                        tracing::warn!("missing username in the JWT claims");
                    }
                    username.map(|s| s.to_string())
                } else {
                    tracing::info!("reading username from fields");
                    let username = auth
                        .fields
                        .get("claims")
                        .ok_or_else(|| "missing claims in fields")
                        .and_then(|claims| {
                            claims
                                .as_object()
                                .ok_or_else(|| "claims in fields must be object")
                        })
                        .and_then(|claims| {
                            claims
                                .get("cognito:username")
                                .ok_or_else(|| "missing username in claims in fields")
                        })
                        .and_then(|username| {
                            username
                                .as_str()
                                .ok_or_else(|| "username in the claims in fields must be string")
                        })
                        .map(|s| Some(s.to_string()));
                    username.unwrap_or_else(|e| {
                        tracing::warn!("{e}");
                        None
                    })
                }
            });
        let secret_message = match user_id {
            Some(user_id) => format!(
                r#"{{"message": "{}, you are allowed to see this!"}}"#,
                user_id
            ),
            None => r#"{"message": "Well, you are not supposed to see this..."}"#.to_string(),
        };
        Ok(Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            // proxy integration needs this
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from(secret_message))
            .expect("failed to render response"))
    } else {
        tracing::error!("unsupported path: {}", event.raw_http_path());
        Ok(Response::builder()
            .status(404)
            .header("Content-Type", "text/plain")
            // proxy integration needs this
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from("not found"))
            .expect("failed to render response"))
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
