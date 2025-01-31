//! Discoverable credential authentication.
//!
//! This application is intended to run as an AWS Lambda function.
//!
//! You have to configure the following environment variables:
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table that manages sessions
//! - `RP_ORIGIN_PARAMETER_PATH`: path to the parameter that stores the origin
//!   (URL) of the relying party in the Parameter Store on AWS Systems Manager
//!
//! ## Action
//!
//! Starts authentication of a client-side discoverable credential.
//! No request body is required.
//! The response body is a JSON representation of
//! [`RequestChallengeResponse`](https://docs.rs/webauthn-rs/latest/webauthn_rs/prelude/struct.RequestChallengeResponse.html).
//!
//! There is no endpoint to finish the authentication, because subsequent steps
//! are processed by Cognito triggers.

use aws_sdk_dynamodb::{
    primitives::DateTime,
    types::AttributeValue,
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE_NO_PAD as base64url},
};
use lambda_runtime::{Error, LambdaEvent, run, service_fn};
use serde_json::Value;
use std::env;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::RequestChallengeResponse};

use authentication::error_response::ErrorResponse;
use authentication::parameters::load_relying_party_origin;
use authentication::sdk_error_ext::SdkErrorExt as _;

// State shared among Lambda invocations.
struct SharedState {
    webauthn: Webauthn,
    dynamodb: aws_sdk_dynamodb::Client,
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
        Ok(Self {
            webauthn,
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            session_table_name: env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be set"))?,
        })
    }
}

async fn function_handler(
    shared_state: Arc<SharedState>,
    _event: LambdaEvent<Value>,
) -> Result<RequestChallengeResponse, ErrorResponse> {
    start_authentication(shared_state).await
}

async fn start_authentication(
    shared_state: Arc<SharedState>,
) -> Result<RequestChallengeResponse, ErrorResponse> {
    info!("start_authentication");
    let (rcr, auth_state) = shared_state.webauthn.start_discoverable_authentication()?;
    let ttl = DateTime::from(SystemTime::now()).secs() + 60;
    info!("putting authentication session: {}", base64url.encode(&rcr.public_key.challenge));
    shared_state.dynamodb
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
        .await
        .map_err(|e| if e.is_retryable() {
            ErrorResponse::unavailable("service temporarily unavailable")
        } else {
            e.into()
        })?;
    Ok(rcr)
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
    use webauthn_rs::prelude::Url;

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
                session_table_name,
            }
        }
    }

    impl Default for SharedState {
        fn default() -> Self {
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
                session_table_name: "sessions".to_string(),
            }
        }
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_ok() {
        let state = Arc::new(SharedState::default());
        assert!(start_authentication(state).await.is_ok());
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

        let res = start_authentication(state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unhandled(_)));
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
        let res = start_authentication(state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb.clone(),
            "sessions_request_cap",
        ));
        let res = start_authentication(state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb.clone(),
            "sessions_throttled",
        ));
        let res = start_authentication(state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));

        let state = Arc::new(SharedState::with_dynamodb_and_session_table_name(
            dynamodb,
            "sessions_unavailable",
        ));
        let res = start_authentication(state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
    }
}
