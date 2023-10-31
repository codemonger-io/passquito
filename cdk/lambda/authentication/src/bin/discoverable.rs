//! Discoverable credential authentication.
//!
//! You have to configure the following environment variables:
//! - `BASE_PATH`: base path to provide the service; e.g, `/auth/credentials/discoverable/`
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table that manages sessions
//!
//! ## Endpoint
//!
//! Provides the following endpoint under the base path.
//!
//! ### `POST ${BASE_PATH}start`
//!
//! Starts authentication of a client-side discoverable credential.
//! No request body is required.
//! The response body is [`RequestChallengeResponse`] as `application/json`.
//!
//! There is not endpoint to finish the authentication, because subsequent steps are processed by Cognito triggers.

use aws_sdk_dynamodb::{
    primitives::DateTime,
    types::AttributeValue,
};
use lambda_http::{
    Body,
    Error,
    Request,
    RequestExt,
    Response,
    http::StatusCode,
    run,
    service_fn,
};
use std::env;
use std::time::SystemTime;
use tracing::{error, info};
use webauthn_rs::{
    WebauthnBuilder,
    prelude::Url,
};

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    let base_path = env::var("BASE_PATH")
        .or(Err("BASE_PATH env must be specified"))?;
    let base_path = base_path.trim_end_matches('/');
    let job_path = event.raw_http_path().strip_prefix(base_path)
        .ok_or(format!("path must start with {}", base_path))?;
    match job_path {
        "/start" => start_authentication().await,
        _ => Err(format!("unsupported job path: {}", job_path).into()),
    }
}

async fn start_authentication() -> Result<Response<Body>, Error> {
    info!("start_authentication");
    // TODO: reuse Webauthn
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:5173")?;
    let webauthn = WebauthnBuilder::new(rp_id, &rp_origin)?
        .rp_name("Passkey Test")
        .build()?;
    let res = match webauthn.start_discoverable_authentication() {
        Ok((rcr, auth_state)) => {
            // TODO: reuse DynamoDB client
            let session_table_name = env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be specified"))?;
            let config = aws_config::load_from_env().await;
            let dynamodb = aws_sdk_dynamodb::Client::new(&config);
            let ttl = DateTime::from(SystemTime::now()).secs() + 60;
            info!("putting authentication session: {}", rcr.public_key.challenge);
            dynamodb.put_item()
                .table_name(session_table_name)
                .item("pk", AttributeValue::S(format!("discoverable#{}", rcr.public_key.challenge)))
                .item("ttl", AttributeValue::N(ttl.to_string()))
                .item("state", AttributeValue::S(serde_json::to_string(&auth_state)?))
                .send()
                .await?;
            serde_json::to_string(&rcr)?
        }
        Err(e) => {
            error!("failed to start authentication: {}", e);
            return Err("failed to start authentication".into());
        }
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(res.into())?)
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