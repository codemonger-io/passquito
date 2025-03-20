//! Facade for AWS Cognito
//!
//! This application is intended to run as an AWS Lambda function.
//!
//! You have to configure the following environment variable:
//! - `USER_POOL_CLIENT_ID`: ID of the Cognito user pool client
//!
//! ## Actions
//!
//! Provides the following actions dependeing on the request payload.
//!
//! ### Start
//!
//! Wraps a [`InitiateAuth`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) API call.
//!
//! To initiate an authentication session, the request body must be in the
//! following form which is a serialized representation of
//! [`CognitoAcition::InitiateAuth`]:
//!
//! ```json
//! {
//!   "start": {
//!     "userId": "userId"
//!   }
//! }
//! ```
//!
//! The following inputs will be passed to the `InitiateAuth` API:
//! - `ClientId`: value of the `USER_POOL_CLIENT_ID` environment variable
//! - `AuthFlow`: `"CUSTOM_AUTH"`
//! - `AuthParameters`:
//!   - `USERNAME`: `userId`
//!
//! A successful response will be in the following form which is a serialized
//! representation of [`AuthenticationSession`].
//!
//! ```json
//! {
//!   "session": "session",
//!   "credentialRequestOptions": {
//!     "publicKey": { ... }
//!   }
//! }
//! ```
//!
//! `session` is the session token that must be passed to the `Finish` action.
//! `credentialRequestOptions` represents a
//! [WebAuthn extension of the `CredentialRequestOptions`](https://www.w3.org/TR/webauthn-3/#sctn-credentialrequestoptions-extension).
//!
//! ### Finish
//!
//! Wraps a [`RespondToAuthChallenge`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html) API call.
//!
//! To finish the authentication session, the request body must be in the
//! following form which is a serialized representation of
//! [`CognitoAction::Finish`]:
//!
//! ```json
//! {
//!   "finish": {
//!     "session": "session",
//!     "userId": "userId",
//!     "answer": "credential"
//!   }
//! }
//! ```
//!
//! `session` must be the session token returned by the `Start` action.
//! `answer` must be a JSON-stringified form of the credential signed by the
//! authenticator of the user.
//! The challenge signed by the authenticator may be either:
//! - a challenge issued by the `Start` action
//! - a challenge issued by the discoverable authentication endpoint
//!
//! The following inputs will be passed to the `RespondToAuthChallenge` API:
//! - `ClientId`: value of the `USER_POOL_CLIENT_ID` environment variable
//! - `ChallengeName`: `"CUSTOM_CHALLENGE"`
//! - `Session`: `session`
//! - `ChallengeResponses`:
//!   - `USERNAME`: `userId`
//!   - `ANSWER`: `answer`
//!
//! A successful response will be a serialized representation of
//! [`AuthenticationResultType`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AuthenticationResultType.html).
//!
//! ### Refresh Token
//!
//! TBD

use aws_sdk_cognitoidentityprovider::types::AuthFlowType;
use lambda_runtime::{Error, LambdaEvent, run, service_fn};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use tracing::{error, info};
use webauthn_rs::prelude::RequestChallengeResponse;

use authentication::error_response::ErrorResponse;

// TODO: move to the library module
const CHALLENGE_PARAMETER_NAME: &str = "passkeyTestChallenge";

#[cfg_attr(test, derive(drive_builder::Builder))]
#[cfg_attr(test, builder(setter(into), pattern = "owned"))]
struct SharedState {
    cognito: aws_sdk_cognitoidentityprovider::Client,
    #[cfg_attr(test, builder(default = "\"123456789\".to_string()"))]
    user_pool_client_id: String,
}

impl SharedState {
    async fn new() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self {
            cognito: aws_sdk_cognitoidentityprovider::Client::new(&config),
            user_pool_client_id: env::var("USER_POOL_CLIENT_ID")
                .or(Err("USER_POOL_CLIENT_ID env must be set"))?,
        })
    }
}

/// Actions that can be performed by the Lambda function.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum CognitoAction {
    /// Start an authentication session.
    #[serde(rename_all = "camelCase")]
    Start {
        /// User ID to authenticate, which was issued by Passquito.
        user_id: String,
    },
}

async fn function_handler(
    shared_state: Arc<SharedState>,
    event: LambdaEvent<serde_json::Value>,
) -> Result<serde_json::Value, ErrorResponse> {
    // parses the payload into the action to perform
    let (action, _) = event.into_parts();
    let action: CognitoAction = serde_json::from_value(action)?;
    match action {
        CognitoAction::Start { user_id } => {
            start_authentication(shared_state, user_id).await
                .and_then(|session| serde_json::to_value(session)
                    .map_err(|e| {
                        error!("failed to serialize the response: {e:?}");
                        e.into()
                    }))
        }
    }
}

/// Authentication session initiated by a `Start` action.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationSession {
    /// Session token to be passed to the `Finish` action.
    session: String,
    /// WebAuthn extension of credential request options.
    credential_request_options: RequestChallengeResponse,
}

async fn start_authentication(
    shared_state: Arc<SharedState>,
    user_id: String,
) -> Result<AuthenticationSession, ErrorResponse> {
    info!("start_authentication: {user_id}");
    let res = shared_state.cognito.initiate_auth()
        .client_id(&shared_state.user_pool_client_id)
        .auth_flow(AuthFlowType::CustomAuth)
        .auth_parameters("USERNAME", user_id)
        .send()
        .await?;
    // TODO: challenge_name must be "CUSTOM_CHALLENGE"

    // retrieves the session token
    let session = res.session.ok_or_else(|| "no session token")?;

    // retrieves the credential request options
    let challenge_parameter = res.challenge_parameters
        .as_ref()
        .ok_or_else(|| "no challenge parameters")?
        .get(CHALLENGE_PARAMETER_NAME)
        .ok_or_else(|| "no Passquito challenge parameter")?;

    // challenge parameter must represent the credential request options
    let credential_request_options = serde_json::from_str(challenge_parameter)?;

    Ok(AuthenticationSession {
        session,
        credential_request_options,
    })
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

