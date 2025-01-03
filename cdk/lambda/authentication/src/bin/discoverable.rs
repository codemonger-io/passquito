//! Discoverable credential authentication.
//!
//! You have to configure the following environment variables:
//! - `BASE_PATH`: base path to provide the service; e.g, `/auth/credentials/discoverable/`
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table that manages sessions
//! - `RP_ORIGIN_PARAMETER_PATH`: path to the parameter that stores the origin
//!   (URL) of the relying party in the Parameter Store on AWS Systems Manager
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
//! There is no endpoint to finish the authentication, because subsequent steps
//! are processed by Cognito triggers.

use aws_sdk_dynamodb::{
    config::http::HttpResponse,
    error::SdkError,
    operation::put_item::PutItemError,
    primitives::DateTime,
    types::AttributeValue,
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE_NO_PAD as base64url},
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
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, info};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use authentication::parameters::load_relying_party_origin;
use authentication::sdk_error_ext::SdkErrorExt as _;

// State shared among Lambda invocations.
struct SharedState {
    webauthn: Webauthn,
    dynamodb: aws_sdk_dynamodb::Client,
    base_path: String,
    session_table_name: String,
}

impl SharedState {
    async fn new() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let (rp_id, rp_origin) =
            load_relying_party_origin(aws_sdk_ssm::Client::new(&config)).await?;
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name("Passkey Test")
            .build()?;
        let base_path = env::var("BASE_PATH")
            .or(Err("BASE_PATH env must be set"))?;
        Ok(Self {
            webauthn,
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            base_path: base_path.trim_end_matches('/').into(),
            session_table_name: env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be set"))?,
        })
    }
}

async fn function_handler(
    shared_state: Arc<SharedState>,
    event: Request,
) -> Result<Response<Body>, Error> {
    let job = event
        .raw_http_path()
        .strip_prefix(&shared_state.base_path)
        .and_then(|job_path| match job_path {
            "/start" => Some(start_authentication(shared_state)),
            _ => None,
        });
    if let Some(job) = job {
        job.await
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body("bad request".into())?)
    }
}

async fn start_authentication(
    shared_state: Arc<SharedState>,
) -> Result<Response<Body>, Error> {
    info!("start_authentication");
    let res = match shared_state.webauthn.start_discoverable_authentication() {
        Ok((rcr, auth_state)) => {
            let ttl = DateTime::from(SystemTime::now()).secs() + 60;
            info!("putting authentication session: {}", base64url.encode(&rcr.public_key.challenge));
            let res = shared_state.dynamodb
                .put_item()
                .table_name(shared_state.session_table_name.clone())
                .item(
                    "pk",
                    AttributeValue::S(
                        format!("discoverable#{}", base64url.encode(&rcr.public_key.challenge)),
                    ),
                )
                .item("ttl", AttributeValue::N(ttl.to_string()))
                .item(
                    "state",
                    AttributeValue::S(serde_json::to_string(&auth_state)?),
                )
                .send()
                .await;
            if is_retryable_error(&res) {
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Content-Type", "text/plain")
                    .body("service temporarily unavailable".into())?);
            }
            res?;
            serde_json::to_string(&rcr)?
        }
        Err(e) => {
            error!("failed to start authentication: {}", e);
            return Err("failed to start authentication".into());
        }
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(res.into())?)
}

fn is_retryable_error<T>(res: &Result<T, SdkError<PutItemError, HttpResponse>>) -> bool {
    match res {
        Err(e) => e.is_retryable(),
        Ok(_) => false,
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

    let shared_state = Arc::new(SharedState::new().await?);
    run(service_fn(|req| async {
        function_handler(shared_state.clone(), req).await
    })).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_sdk_dynamodb::operation::put_item::PutItemOutput;
    use aws_smithy_mocks_experimental::{mock, MockResponseInterceptor, RuleMode};
    use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
    use aws_smithy_runtime_api::http::StatusCode as SmithyStatusCode;
    use aws_smithy_types::body::SdkBody;
    use webauthn_rs::prelude::{RequestChallengeResponse, Url};

    impl SharedState {
        fn with_dynamodb_and_session_table_name(
            dynamodb: aws_sdk_dynamodb::Client,
            session_table_name: impl Into<String>,
        ) -> Self {
            let session_table_name = session_table_name.into();
            let rp_id = "localhost".to_string();
            let rp_origin = Url::parse("http://localhost:5173").unwrap();
            SharedState {
                webauthn: WebauthnBuilder::new(&rp_id, &rp_origin)
                    .unwrap()
                    .rp_name("Passkey Test")
                    .build()
                    .unwrap(),
                dynamodb,
                base_path: "/discoverable".to_string(),
                session_table_name,
            }
        }

        fn with_base_path(base_path: impl Into<String>) -> Self {
            let base_path = base_path.into();

            let rp_id = "localhost".to_string();
            let rp_origin = Url::parse("http://localhost:5173").unwrap();

            let put_item_ok = mock!(aws_sdk_dynamodb::Client::put_item)
                .then_output(|| PutItemOutput::builder().build());
            let put_item_mocks = MockResponseInterceptor::new()
                .rule_mode(RuleMode::MatchAny)
                .with_rule(&put_item_ok);
            let dynamodb = aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .with_test_defaults()
                    .region(aws_sdk_dynamodb::config::Region::new("ap-northeast-1"))
                    .interceptor(put_item_mocks)
                    .build(),
            );

            SharedState {
                webauthn: WebauthnBuilder::new(&rp_id, &rp_origin)
                    .unwrap()
                    .rp_name("Passkey Test")
                    .build()
                    .unwrap(),
                dynamodb,
                base_path,
                session_table_name: "sessions".to_string(),
            }
        }
    }

    impl Default for SharedState {
        fn default() -> Self {
            SharedState::with_base_path("/discoverable")
        }
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_ok() {
        let state = Arc::new(SharedState::default());
        let res = start_authentication(state).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(serde_json::from_slice::<RequestChallengeResponse>(res.body()).is_ok());
    }

    const RESOURCE_NOT_FOUND_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException", "message": "Requested resource not found: Table: sessions not found"}"#;

    const PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "message": "Exceeded provisioned throughput."}"#;

    const REQUEST_LIMIT_EXCEEDED: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#RequestLimitExceeded", "message": "Exceeded request limit."}"#;

    const THROTTLING_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ThrottlingException", "message": "Request throttled"}"#;

    const SERVICE_UNAVAILABLE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ServiceUnavailable", "message": "Service temporarily unavailable"}"#;

    #[tokio::test]
    async fn start_authentication_with_put_item_with_non_retryable_error() {
        let put_item_not_found = mock!(aws_sdk_dynamodb::Client::put_item)
            .then_http_response(|| {
                HttpResponse::new(
                    SmithyStatusCode::try_from(400).unwrap(),
                    SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION),
                )
            });

        let put_item_mocks = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&put_item_not_found);

        let dynamodb = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .with_test_defaults()
                .region(aws_sdk_dynamodb::config::Region::new("ap-northeast-1"))
                .interceptor(put_item_mocks)
                .build(),
        );

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb,
            "sessions",
        ));

        assert!(start_authentication(state).await.is_err());
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_with_retryable_errors() {
        let put_item_throughput_cap = mock!(aws_sdk_dynamodb::Client::put_item)
            .match_requests(|req| req.table_name() == Some("sessions_throughput_cap"))
            .then_http_response(|| {
                HttpResponse::new(
                    SmithyStatusCode::try_from(400).unwrap(),
                    SdkBody::from(PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION),
                )
            });

        let put_item_request_cap = mock!(aws_sdk_dynamodb::Client::put_item)
            .match_requests(|req| req.table_name() == Some("sessions_request_cap"))
            .then_http_response(|| {
                HttpResponse::new(
                    SmithyStatusCode::try_from(400).unwrap(),
                    SdkBody::from(REQUEST_LIMIT_EXCEEDED),
                )
            });

        let put_item_throttled = mock!(aws_sdk_dynamodb::Client::put_item)
            .match_requests(|req| req.table_name() == Some("sessions_throttled"))
            .then_http_response(|| {
                HttpResponse::new(
                    SmithyStatusCode::try_from(400).unwrap(),
                    SdkBody::from(THROTTLING_EXCEPTION),
                )
            });

        let put_item_unavailable = mock!(aws_sdk_dynamodb::Client::put_item)
            .match_requests(|req| req.table_name() == Some("sessions_unavailable"))
            .then_http_response(|| {
                HttpResponse::new(
                    SmithyStatusCode::try_from(503).unwrap(),
                    SdkBody::from(SERVICE_UNAVAILABLE),
                )
            });

        let put_item_mocks = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&put_item_throughput_cap)
            .with_rule(&put_item_request_cap)
            .with_rule(&put_item_throttled)
            .with_rule(&put_item_unavailable);

        let dynamodb = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .with_test_defaults()
                .region(aws_sdk_dynamodb::config::Region::new("ap-northeast-1"))
                .interceptor(put_item_mocks)
                .build(),
        );

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb.clone(),
            "sessions_throughput_cap",
        ));
        let res = start_authentication(state).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb.clone(),
            "sessions_request_cap",
        ));
        let res = start_authentication(state).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb.clone(),
            "sessions_throttled",
        ));
        let res = start_authentication(state).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb,
            "sessions_unavailable",
        ));
        let res = start_authentication(state).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn function_handler_with_valid_path() {
        let state = Arc::new(SharedState::with_base_path("/discoverable"));

        let req = Request::default().with_raw_http_path("/discoverable/start");

        let res = function_handler(state, req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(serde_json::from_slice::<RequestChallengeResponse>(res.body()).is_ok());
    }

    #[tokio::test]
    async fn function_handler_with_invalid_path_prefix() {
        let state = Arc::new(SharedState::with_base_path("/discoverable"));

        let req = Request::default().with_raw_http_path("/start-discovery");

        let res = function_handler(state, req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn function_handler_with_invalid_job_path() {
        let state = Arc::new(SharedState::with_base_path("/discoverable"));

        let req = Request::default().with_raw_http_path("/discoverable/finish");

        let res = function_handler(state, req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
