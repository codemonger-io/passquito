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
#[cfg_attr(test, derive(derive_builder::Builder))]
#[cfg_attr(test, builder(setter(into), pattern = "owned"))]
struct SharedState {
    #[cfg_attr(test, builder(default = "self::tests::mocks::webauthn::new_webauthn()"))]
    webauthn: Webauthn,
    dynamodb: aws_sdk_dynamodb::Client,
    #[cfg_attr(test, builder(default = "\"sessions\".to_string()"))]
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

    use aws_smithy_mocks_experimental::{MockResponseInterceptor, RuleMode};

    #[tokio::test]
    async fn start_authentication_with_put_item_ok() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&mocks::dynamodb::put_item_ok());

        let shared_state = SharedStateBuilder::default()
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        assert!(start_authentication(shared_state).await.is_ok());
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_resource_not_found() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&mocks::dynamodb::put_item_resource_not_found());

        let shared_state = SharedStateBuilder::default()
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = start_authentication(shared_state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unhandled(_)));
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_provisioned_throughput_exceeded() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_provisioned_throughput_exceeded());

        let shared_state = SharedStateBuilder::default()
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = start_authentication(shared_state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_request_request_limit_exceeded() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_request_limit_exceeded());

        let shared_state = SharedStateBuilder::default()
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = start_authentication(shared_state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_throttling_exception() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_throttling_exception());

        let shared_state = SharedStateBuilder::default()
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = start_authentication(shared_state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_authentication_with_put_item_service_unavailable() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_service_unavailable());

        let shared_state = SharedStateBuilder::default()
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = start_authentication(shared_state).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
    }

    pub(crate) mod mocks {
        use super::*;

        pub(crate) mod webauthn {
            use super::*;

            use webauthn_rs::prelude::Url;

            pub(crate) fn new_webauthn() -> Webauthn {
                let rp_id = "localhost".to_string();
                let rp_origin = Url::parse("http://localhost:5173").unwrap();
                WebauthnBuilder::new(&rp_id, &rp_origin)
                    .unwrap()
                    .rp_name("Passkey Test")
                    .build()
                    .unwrap()
            }
        }

        pub(crate) mod dynamodb {
            use super::*;

            use aws_sdk_dynamodb::{
                config::Region,
                operation::put_item::PutItemOutput,
                Client,
                Config,
            };
            use aws_smithy_mocks_experimental::{mock, Rule};
            use aws_smithy_runtime_api::{
                client::orchestrator::HttpResponse,
                http::StatusCode as SmithyStatusCode,
            };
            use aws_smithy_types::body::SdkBody;

            const RESOURCE_NOT_FOUND_EXCEPTION_RESPONSE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException", "message": "Requested resource not found: Table: sessions not found"}"#;

            const PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION_RESPONSE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "message": "Exceeded provisioned throughput."}"#;

            const REQUEST_LIMIT_EXCEEDED_RESPONSE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#RequestLimitExceeded", "message": "Exceeded request limit."}"#;

            const THROTTLING_EXCEPTION_RESPONSE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ThrottlingException", "message": "Request throttled"}"#;

            const SERVICE_UNAVAILABLE_RESPONSE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ServiceUnavailable", "message": "Service temporarily unavailable"}"#;

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .interceptor(mocks)
                        .region(Region::new("ap-northeast-1"))
                        .build()
                )
            }

            pub(crate) fn put_item_ok() -> Rule {
                mock!(Client::put_item)
                    .then_output(|| PutItemOutput::builder().build())
            }

            pub(crate) fn put_item_resource_not_found() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn put_item_provisioned_throughput_exceeded() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn put_item_request_limit_exceeded() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(REQUEST_LIMIT_EXCEEDED_RESPONSE),
                        )
                    })
            }

            pub(crate) fn put_item_throttling_exception() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(THROTTLING_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn put_item_service_unavailable() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(503).unwrap(),
                            SdkBody::from(SERVICE_UNAVAILABLE_RESPONSE),
                        )
                    })
            }
        }
    }
}
