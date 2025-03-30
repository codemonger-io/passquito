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
//! Wraps an [`InitiateAuth`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) API call.
//!
//! To initiate an authentication session, the request body must be in the
//! following form which is a serialized representation of
//! [`CognitoAction::Start`]:
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
//!   "sessionId": "Session ID",
//!   "credentialRequestOptions": {
//!     "publicKey": { ... }
//!   }
//! }
//! ```
//!
//! `sessionId` is the session ID that must be passed to the `Finish` action.
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
//!     "sessionId": "Session ID",
//!     "userId": "userId",
//!     "publicKey": { ... }
//!   }
//! }
//! ```
//!
//! `sessionId` must be the session token returned by the `Start` action.
//! `publicKey` must be a [public key credential](https://www.w3.org/TR/webauthn-3/#iface-pkcredential)
//! signed by the authenticator of the user.
//! The challenge signed by the authenticator may be either:
//! - a challenge issued by the `Start` action
//! - a challenge issued by the discoverable authentication endpoint
//!
//! The following inputs will be passed to the `RespondToAuthChallenge` API:
//! - `ClientId`: value of the `USER_POOL_CLIENT_ID` environment variable
//! - `ChallengeName`: `"CUSTOM_CHALLENGE"`
//! - `Session`: `sessionId`
//! - `ChallengeResponses`:
//!   - `USERNAME`: `userId`
//!   - `ANSWER`: `publicKey`
//!
//! A successful response will be in the following form which is a serialized
//! representation of a [`AuthenticationResult`].
//!
//! ```json
//! {
//!   "accessToken": "AccessToken",
//!   "expiresIn": 123,
//!   "idToken": "IdToken",
//!   "refreshToken": "RefreshToken"
//! }
//! ```
//!
//! ### Refresh Tokens
//!
//! Wraps an [`InitiateAuth`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) API call for refreshing tokens.
//!
//! To refresh tokens, the request body must be in the following form which is
//! a serialized representation of [`CognitoAction::Refresh`]:
//!
//! ```json
//! {
//!   "refresh": {
//!     "refreshToken": "RefreshToken"
//!   }
//! }
//! ```
//!
//! `refreshToken` must be a valid refresh token issued by the Cognito user
//! pool.
//!
//! The following inputs will be passed to the `InitiateAuth` API:
//! - `ClientId`: value of the `USER_POOL_CLIENT_ID` environment variable
//! - `AuthFlow`: `"REFRESH_TOKEN_AUTH"`
//! - `AuthParameters`:
//!   - `REFRESH_TOKEN`: `refreshToken`
//!
//! A successful response will be in the following form which is a serialized
//! representation of a [`AuthenticationResult`].
//!
//! ```json
//! {
//!   "accessToken": "AccessToken",
//!   "expiresIn": 123,
//!   "idToken": "IdToken",
//!   "refreshToken": "RrefreshToken"
//! }
//! ```
//!
//! `refreshToken` is the same as the input.

use aws_sdk_cognitoidentityprovider::{
    operation::{
        initiate_auth::InitiateAuthError,
        respond_to_auth_challenge::RespondToAuthChallengeError,
    },
    types::{
        AuthFlowType,
        AuthenticationResultType,
        ChallengeNameType,
        NewDeviceMetadataType,
    },
};
use lambda_runtime::{Error, LambdaEvent, run, service_fn};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use tracing::{error, info};
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use authentication::error_response::ErrorResponse;
use authentication::sdk_error_ext::is_common_retryable_error;

// TODO: move to the library module
const CHALLENGE_PARAMETER_NAME: &str = "passkeyTestChallenge";

#[cfg_attr(test, derive(derive_builder::Builder))]
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
    /// Starts an authentication session.
    #[serde(rename_all = "camelCase")]
    Start {
        /// User ID to authenticate, which was issued by Passquito.
        user_id: String,
    },
    /// Finishes an authentication session.
    Finish(FinishPayload),
    /// Refreshes tokens.
    #[serde(rename_all = "camelCase")]
    Refresh {
        /// Refresh token issued by the Cognito user pool.
        refresh_token: String,
    },
}

/// Answer to an authentication session.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinishPayload {
    /// Session token issued by the [`CognitoAction::Start`] action.
    session_id: String,
    /// User ID to authenticate, which was issued by Passquito.
    user_id: String,
    /// Public key credential signed by the authenticator of the user.
    public_key: PublicKeyCredential,
}

/// Authentication session initiated by a `Start` action.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
struct AuthenticationSession {
    /// Session token to be passed to the `Finish` action.
    session_id: String,
    /// WebAuthn extension of credential request options.
    credential_request_options: RequestChallengeResponse,
}

/// Authentication result.
///
/// A serialized representation of this struct is a "camelCase" version of
/// a subset of [`AuthenticationResultType`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AuthenticationResultType.html).
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
struct AuthenticationResult {
    /// AccessToken.
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    /// ExpiresIn.
    expires_in: i32,
    /// TokenType.
    /// RefreshToken.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    /// IdToken.
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

impl From<AuthenticationResultType> for AuthenticationResult {
    #[inline]
    fn from(from: AuthenticationResultType) -> Self {
        Self {
            access_token: from.access_token,
            expires_in: from.expires_in,
            refresh_token: from.refresh_token,
            id_token: from.id_token,
        }
    }
}

/// New device metadata in an authentication result.
///
/// A serialized representation of this struct is a "camelCase" version of
/// [`NewDeviceMetadataType`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_NewDeviceMetadataType.html).
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
struct NewDeviceMetadata {
    /// DeviceKey.
    #[serde(skip_serializing_if = "Option::is_none")]
    device_key: Option<String>,
    /// DeviceGroupKey.
    #[serde(skip_serializing_if = "Option::is_none")]
    device_group_key: Option<String>,
}

impl From<NewDeviceMetadataType> for NewDeviceMetadata {
    #[inline]
    fn from(from: NewDeviceMetadataType) -> Self {
        Self {
            device_key: from.device_key,
            device_group_key: from.device_group_key,
        }
    }
}

async fn function_handler(
    shared_state: Arc<SharedState>,
    event: LambdaEvent<serde_json::Value>,
) -> Result<serde_json::Value, ErrorResponse> {
    // parses the payload into the action to perform
    let (action, _) = event.into_parts();
    let action: CognitoAction = serde_json::from_value(action)
        .map_err(|e| {
            error!("invalid request payload: {e:?}");
            ErrorResponse::BadRequest("invalid request payload".to_string())
        })?;
    match action {
        CognitoAction::Start { user_id } => {
            let res = start_authentication(shared_state, user_id).await;
            res.and_then(|res| serde_json::to_value(res).map_err(Into::into))
        }
        CognitoAction::Finish(payload) => {
            let res = finish_authentication(shared_state, payload).await;
            res.and_then(|res| serde_json::to_value(res).map_err(Into::into))
        }
        CognitoAction::Refresh { refresh_token } => {
            let res = refresh_tokens(shared_state, refresh_token).await;
            res.and_then(|res| serde_json::to_value(res).map_err(Into::into))
        }
    }.map_err(|e| {
        match e {
            ErrorResponse::Unhandled(e) => {
                // never exposes the details of an unhandled error
                error!("{e:?}");
                "internal server error".into()
            }
            _ => e,
        }
    })
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
        .await
        .map_err(|e| match e.into_service_error() {
            InitiateAuthError::NotAuthorizedException(e) => {
                error!("{e:?}");
                ErrorResponse::unauthorized("not authorized")
            }
            InitiateAuthError::UserNotFoundException(e) => {
                error!("{e:?}");
                ErrorResponse::unauthorized("not authorized")
            }
            InitiateAuthError::TooManyRequestsException(e) => {
                error!("{e:?}");
                ErrorResponse::unavailable("too many requests")
            }
            e if is_common_retryable_error(&e) => {
                error!("{e:?}");
                ErrorResponse::unavailable("service unavailable")
            }
            e => e.into(),
        })?;
    if res.challenge_name != Some(ChallengeNameType::CustomChallenge) {
        error!("challenge name must be \"CUSTOM_CHALLENGE\" but got {:?}", res.challenge_name);
        return Err(ErrorResponse::bad_configuration("bad user pool configuration"));
    }

    // retrieves the session ID
    let session_id = res.session.ok_or_else(|| "no session ID")?;

    // retrieves the credential request options
    let challenge_parameter = res.challenge_parameters
        .as_ref()
        .ok_or_else(|| ErrorResponse::bad_configuration("bad user pool configuration"))?
        .get(CHALLENGE_PARAMETER_NAME)
        .ok_or_else(|| ErrorResponse::bad_configuration("bad user pool configuration"))?;

    // challenge parameter must represent the credential request options
    let credential_request_options = serde_json::from_str(challenge_parameter)
        .map_err(|e| {
            error!("{e:?}");
            ErrorResponse::bad_configuration("bad user pool configuration")
        })?;

    Ok(AuthenticationSession {
        session_id,
        credential_request_options,
    })
}

async fn finish_authentication(
    shared_state: Arc<SharedState>,
    payload: FinishPayload,
) -> Result<AuthenticationResult, ErrorResponse> {
    info!("finish_authentication: {}", payload.user_id);
    let res = shared_state.cognito.respond_to_auth_challenge()
        .client_id(&shared_state.user_pool_client_id)
        .challenge_name(ChallengeNameType::CustomChallenge)
        .session(&payload.session_id)
        .challenge_responses("USERNAME", payload.user_id)
        .challenge_responses("ANSWER", serde_json::to_string(&payload.public_key)?)
        .send()
        .await
        .map_err(|e| match e.into_service_error() {
            RespondToAuthChallengeError::NotAuthorizedException(e) => {
                error!("{e:?}");
                ErrorResponse::unauthorized("not authorized")
            }
            RespondToAuthChallengeError::UserNotFoundException(e) => {
                error!("{e:?}");
                ErrorResponse::unauthorized("not authorized")
            }
            RespondToAuthChallengeError::TooManyRequestsException(e) => {
                error!("{e:?}");
                ErrorResponse::unavailable("too many requests")
            }
            e if is_common_retryable_error(&e) => {
                error!("{e:?}");
                ErrorResponse::unavailable("service unavailable")
            }
            e => e.into(),
        })?;
    let result = res.authentication_result
        .ok_or_else(|| "authentication result must be set")?;
    info!("token type: {:?}", result.token_type);
    Ok(result.into())
}

async fn refresh_tokens(
    shared_state: Arc<SharedState>,
    refresh_token: String,
) -> Result<AuthenticationResult, ErrorResponse> {
    info!("refresh_tokens: {refresh_token}");

    let res = shared_state.cognito.initiate_auth()
        .client_id(&shared_state.user_pool_client_id)
        .auth_flow(AuthFlowType::RefreshTokenAuth)
        .auth_parameters("REFRESH_TOKEN", &refresh_token)
        .send()
        .await
        .map_err(|e| match e.into_service_error() {
            InitiateAuthError::NotAuthorizedException(e) => {
                error!("{e:?}");
                ErrorResponse::unauthorized("not authorized")
            }
            InitiateAuthError::TooManyRequestsException(e) => {
                error!("{e:?}");
                ErrorResponse::unavailable("too many requests")
            }
            e if is_common_retryable_error(&e) => {
                error!("{e:?}");
                ErrorResponse::unavailable("service unavailable")
            }
            e => e.into(),
        })?;
    let mut result = res.authentication_result
        .ok_or_else(|| "authentication result must be set")?;
    // refresh token is not returend from the API and has to be reused
    result.refresh_token = Some(refresh_token);
    info!("token type: {:?}", result.token_type);

    Ok(result.into())
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
    async fn function_handler_start() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_ok());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "start": {
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                },
            }),
            lambda_runtime::Context::default(),
        );

        let result = function_handler(shared_state, event).await.unwrap();
        let session: AuthenticationSession = serde_json::from_value(result).unwrap();
        assert_eq!(session.session_id, "ABCDEFGHI");
        assert_eq!(
            serde_json::to_string(&session.credential_request_options.public_key.challenge).unwrap(),
            "\"fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE\"",
        );
    }

    #[tokio::test]
    async fn function_handler_finish() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_ok());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "finish": {
                    "sessionId": "ABCDEFGHI",
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                    "publicKey": self::mocks::webauthn::ok_public_key_credential_as_value()
                },
            }),
            lambda_runtime::Context::default(),
        );

        let result = function_handler(shared_state, event).await.unwrap();
        let result: AuthenticationResult = serde_json::from_value(result).unwrap();
        assert_eq!(result.access_token, Some("AccessToken".to_string()));
        assert_eq!(result.id_token, Some("IdToken".to_string()));
        assert_eq!(result.refresh_token, Some("RefreshToken".to_string()));
        assert_eq!(result.expires_in, 3600);
    }

    #[tokio::test]
    async fn function_handler_refresh() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_refresh_tokens_ok());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "refresh": {
                    "refreshToken": "RefreshToken",
                },
            }),
            lambda_runtime::Context::default(),
        );

        let result = function_handler(shared_state, event).await.unwrap();
        let result: AuthenticationResult = serde_json::from_value(result).unwrap();
        assert_eq!(result.access_token, Some("NewAccessToken".to_string()));
        assert_eq!(result.id_token, Some("NewIdToken".to_string()));
        assert_eq!(result.refresh_token, Some("RefreshToken".to_string()));
        assert_eq!(result.expires_in, 3600);
    }

    #[tokio::test]
    async fn function_handler_bad_request() {
        let cognito = MockResponseInterceptor::new();
        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        // invalid action
        let event = LambdaEvent::new(
            serde_json::json!({
                "unknownAction": {
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                },
            }),
            lambda_runtime::Context::default(),
        );
        let err = function_handler(shared_state.clone(), event).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadRequest(_)));

        // invalid start payload
        let event = LambdaEvent::new(
            serde_json::json!({
                "start": {
                    "unknownField": "UnknownValue",
                },
            }),
            lambda_runtime::Context::default(),
        );
        let err = function_handler(shared_state.clone(), event).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadRequest(_)));

        // finish payload with an invalid public key
        let event = LambdaEvent::new(
            serde_json::json!({
                "finish": {
                    "sessionId": "ABCDEFGHI",
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                    "publicKey": {
                        "unknownField": "invalid public key",
                    },
                },
            }),
            lambda_runtime::Context::default(),
        );
        let err = function_handler(shared_state.clone(), event).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadRequest(_)));
    }

    #[tokio::test]
    async fn function_handler_unhandled_error() {
        // the details of unhandled errors must not be exposed to the caller
        // - start
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_no_session());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "start": {
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                },
            }),
            lambda_runtime::Context::default(),
        );

        let err = function_handler(shared_state, event).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unhandled(msg) if msg.to_string() == "internal server error"));

        // - finish
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_missing_authentication_result());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "finish": {
                    "sessionId": "ABCDEFGHI",
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                    "publicKey": self::mocks::webauthn::ok_public_key_credential_as_value(),
                },
            }),
            lambda_runtime::Context::default(),
        );

        let err = function_handler(shared_state, event).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unhandled(msg) if msg.to_string() == "internal server error"));

        // - refresh
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_refresh_tokens_no_authentication_result());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "refresh": {
                    "refreshToken": "RefreshToken",
                },
            }),
            lambda_runtime::Context::default(),
        );

        let err = function_handler(shared_state, event).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unhandled(msg) if msg.to_string() == "internal server error"));
    }

    #[tokio::test]
    async fn start_authentication_ok() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_ok());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let session = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap();
        assert_eq!(session.session_id, "ABCDEFGHI");
        assert_eq!(
            serde_json::to_string(&session.credential_request_options.public_key.challenge).unwrap(),
            "\"fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE\"",
        )
    }

    #[tokio::test]
    async fn start_authentication_cognito_initiate_auth_not_authorized() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_not_authorized());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn start_authentication_no_challenge_parameters() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_no_challenge_parameters());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadConfiguration(_)));
    }

    #[tokio::test]
    async fn start_authentication_missing_passquito_challenge_parameter() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_missing_passquito_challenge_parameter());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadConfiguration(_)));
    }

    #[tokio::test]
    async fn start_authentication_invalid_credential_request_options() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_invalid_credential_request_options());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadConfiguration(_)));
    }

    #[tokio::test]
    async fn start_authentication_cognito_initiate_auth_user_not_found() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_user_not_found());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn start_authentication_wrong_challenge_name() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_wrong_challenge_name());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::BadConfiguration(_)));
    }

    #[tokio::test]
    async fn start_authentication_cognito_initiate_auth_too_many_requests_exception() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_too_many_requests_exception());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_authentication_cognito_initiate_auth_service_unavailable() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_service_unavailable());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_authentication_cognito_initiate_auth_throttling_exception() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_throttling_exception());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_authentication(
            shared_state,
            "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn finish_authentication_ok() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_ok());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let result = finish_authentication(
            shared_state,
            FinishPayload {
                session_id: "ABCDEFGHI".to_string(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
                public_key: serde_json::from_str(self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL).unwrap(),
            },
        ).await.unwrap();
        assert_eq!(result.access_token, Some("AccessToken".to_string())); 
        assert_eq!(result.id_token, Some("IdToken".to_string()));
        assert_eq!(result.refresh_token, Some("RefreshToken".to_string()));
        assert_eq!(result.expires_in, 3600);
    }

    #[tokio::test]
    async fn finish_authentication_cognito_respond_to_auth_challenge_not_authorized() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_not_authorized());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = finish_authentication(
            shared_state,
            FinishPayload {
                session_id: "ABCDEFGHI".to_string(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
                public_key: serde_json::from_str(self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL).unwrap(),
            },
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn finish_authentication_cognito_respond_to_auth_challenge_user_not_found() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_user_not_found());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = finish_authentication(
            shared_state,
            FinishPayload {
                session_id: "ABCDEFGHI".to_string(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
                public_key: serde_json::from_str(self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL).unwrap(),
            },
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn finish_authentication_cognito_respond_to_auth_challenge_too_many_requests_exception() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_too_many_requests_exception());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = finish_authentication(
            shared_state,
            FinishPayload {
                session_id: "ABCDEFGHI".to_string(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
                public_key: serde_json::from_str(self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL).unwrap(),
            },
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn finish_authentication_cognito_respond_to_auth_challenge_service_unavailable() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_service_unavailable());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = finish_authentication(
            shared_state,
            FinishPayload {
                session_id: "ABCDEFGHI".to_string(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
                public_key: serde_json::from_str(self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL).unwrap(),
            },
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn finish_authentication_cognito_respond_to_auth_challenge_throttling_exception() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::respond_to_auth_challenge_throttling_exception());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = finish_authentication(
            shared_state,
            FinishPayload {
                session_id: "ABCDEFGHI".to_string(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".to_string(),
                public_key: serde_json::from_str(self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL).unwrap(),
            },
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn refresh_tokens_ok() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_refresh_tokens_ok());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let session = refresh_tokens(
            shared_state,
            "RefreshToken".to_string(),
        ).await.unwrap();
        assert_eq!(session.access_token, Some("NewAccessToken".to_string()));
        assert_eq!(session.id_token, Some("NewIdToken".to_string()));
        assert_eq!(session.refresh_token, Some("RefreshToken".to_string()));
        assert_eq!(session.expires_in, 3600);
    }

    #[tokio::test]
    async fn refresh_tokens_cognito_initiate_auth_not_authorized() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_not_authorized());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = refresh_tokens(
            shared_state,
            "RefreshToken".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn refresh_tokens_cognito_initiate_auth_too_many_requests_exception() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_too_many_requests_exception());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = refresh_tokens(
            shared_state,
            "RefreshToken".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn refresh_tokens_cognito_initiate_auth_service_unavailable() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_service_unavailable());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = refresh_tokens(
            shared_state,
            "RefreshToken".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn refresh_tokens_cognito_initiate_auth_throttling_exception() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::initiate_auth_throttling_exception());

        let shared_state = SharedStateBuilder::default()
            .cognito(self::mocks::cognito::new_client(cognito))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = refresh_tokens(
            shared_state,
            "RefreshToken".to_string(),
        ).await.unwrap_err();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    pub(crate) mod mocks {
        use super::*;

        pub(crate) mod webauthn {
            pub(crate) const OK_REQUEST_CHALLENGE_RESPONSE: &str = r#"{
                "publicKey": {
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "rpId": "localhost",
                    "allowCredentials": [],
                    "userVerification": "preferred"
                },
                "mediation": null
            }"#;

            pub(crate) const OK_PUBLIC_KEY_CREDENTIAL: &str = r#"{
                "id": "VD-k4AUT6FLUNmROa7OAiA",
                "rawId": "VD-k4AUT6FLUNmROa7OAiA",
                "response": {
                    "authenticatorData": "",
                    "clientDataJSON": "ewogICJ0eXBlIjogIndlYmF1dGhuLmdldCIsCiAgImNoYWxsZW5nZSI6ICJmU19CMU14Sm91YUkwUXB1WXRyc2w2a2hlQUFxdFFsVWd5QWZheE9ZZFhFIiwKICAib3JpZ2luIjogImh0dHA6Ly9sb2NhbGhvc3QiCn0K",
                    "signature": "",
                    "userHandle": "8TZ_kg_dp_pr0t7SDvGJiw"
                },
                "extensions": {},
                "type": "public-key"
            }"#;
            // the `clientDataJSON` field is a base64url-encoded value of the
            // following JSON:
            // {
            //     "type": "webauthn.get",
            //     "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
            //     "origin": "http://localhost"
            // }

            pub(crate) fn ok_public_key_credential_as_value() -> serde_json::Value {
                serde_json::from_str(OK_PUBLIC_KEY_CREDENTIAL).unwrap()
            }
        }

        pub(crate) mod cognito {
            use super::*;

            use aws_sdk_cognitoidentityprovider::{
                config::Region,
                operation::{
                    initiate_auth::InitiateAuthOutput,
                    respond_to_auth_challenge::RespondToAuthChallengeOutput,
                },
                Client,
                Config,
            };
            use aws_smithy_mocks_experimental::{mock, Rule};
            use aws_smithy_runtime_api::{
                client::orchestrator::HttpResponse,
                http::StatusCode,
            };
            use aws_smithy_types::body::SdkBody;

            const NOT_AUTHORIZED_EXCEPTION_RESPONSE: &str = r#"{
                "__type": "NotAuthorizedException",
                "message": "Incorrect username or password."
            }"#;

            const USER_NOT_FOUND_EXCEPTION_RESPONSE: &str = r#"{
                "__type": "UserNotFoundException",
                "message": "No such user."
            }"#;

            const TOO_MANY_REQUESTS_EXCEPTION_RESPONSE: &str = r#"{
                "__type": "TooManyRequestsException",
                "message": "Too many requests."
            }"#;

            const SERVICE_UNAVAILABLE_RESPONSE: &str = r#"{
                "__type": "ServiceUnavailable",
                "message": "Service unavailable."
            }"#;

            const THROTTLING_EXCEPTION_RESPONSE: &str = r#"{
                "__type": "ThrottlingException",
                "message": "Throttled."
            }"#;

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .region(Region::new("ap-northeast-1"))
                        .interceptor(mocks)
                        .build(),
                )
            }

            pub(crate) fn initiate_auth_ok() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .session("ABCDEFGHI")
                        .challenge_name(ChallengeNameType::CustomChallenge)
                        .challenge_parameters(
                            CHALLENGE_PARAMETER_NAME,
                            super::webauthn::OK_REQUEST_CHALLENGE_RESPONSE,
                        )
                        .build())
            }

            pub(crate) fn initiate_auth_refresh_tokens_ok() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .authentication_result(AuthenticationResultType::builder()
                            .access_token("NewAccessToken")
                            .id_token("NewIdToken")
                            .expires_in(3600)
                            .build())
                        .build())
            }

            pub(crate) fn initiate_auth_wrong_challenge_name() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .session("ABCDEFGHI")
                        .challenge_name(ChallengeNameType::Password)
                        .challenge_parameters(
                            CHALLENGE_PARAMETER_NAME,
                            super::webauthn::OK_REQUEST_CHALLENGE_RESPONSE,
                        )
                        .build())
            }

            pub(crate) fn initiate_auth_no_session() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .challenge_name(ChallengeNameType::CustomChallenge)
                        .challenge_parameters(
                            CHALLENGE_PARAMETER_NAME,
                            super::webauthn::OK_REQUEST_CHALLENGE_RESPONSE,
                        )
                        .build())
            }

            pub(crate) fn initiate_auth_no_challenge_parameters() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .session("ABCDEFGHI")
                        .challenge_name(ChallengeNameType::CustomChallenge)
                        .build())
            }

            pub(crate) fn initiate_auth_missing_passquito_challenge_parameter() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .session("ABCDEFGHI")
                        .challenge_name(ChallengeNameType::CustomChallenge)
                        .challenge_parameters(
                            "UnknownChallengeParameter",
                            super::webauthn::OK_REQUEST_CHALLENGE_RESPONSE,
                        )
                        .build())
            }

            pub(crate) fn initiate_auth_invalid_credential_request_options() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder()
                        .session("ABCDEFGHI")
                        .challenge_name(ChallengeNameType::CustomChallenge)
                        .challenge_parameters(
                            CHALLENGE_PARAMETER_NAME,
                            r#"{ "credential": 123 }"#,
                        )
                        .build())
            }

            pub(crate) fn initiate_auth_refresh_tokens_no_authentication_result() -> Rule {
                mock!(Client::initiate_auth)
                    .then_output(|| InitiateAuthOutput::builder().build())
            }

            pub(crate) fn initiate_auth_not_authorized() -> Rule {
                mock!(Client::initiate_auth)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(NOT_AUTHORIZED_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn initiate_auth_user_not_found() -> Rule {
                mock!(Client::initiate_auth)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(USER_NOT_FOUND_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn initiate_auth_too_many_requests_exception() -> Rule {
                mock!(Client::initiate_auth)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(TOO_MANY_REQUESTS_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn initiate_auth_service_unavailable() -> Rule {
                mock!(Client::initiate_auth)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(503).unwrap(),
                            SdkBody::from(SERVICE_UNAVAILABLE_RESPONSE),
                        )
                    })
            }

            pub(crate) fn initiate_auth_throttling_exception() -> Rule {
                mock!(Client::initiate_auth)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(THROTTLING_EXCEPTION_RESPONSE)
                        )
                    })
            }

            pub(crate) fn respond_to_auth_challenge_ok() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_output(|| RespondToAuthChallengeOutput::builder()
                        .authentication_result(AuthenticationResultType::builder()
                            .access_token("AccessToken")
                            .expires_in(3600)
                            .id_token("IdToken")
                            .refresh_token("RefreshToken")
                            .build())
                        .build())
            }

            pub(crate) fn respond_to_auth_challenge_missing_authentication_result() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_output(|| RespondToAuthChallengeOutput::builder().build())
            }

            pub(crate) fn respond_to_auth_challenge_not_authorized() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(NOT_AUTHORIZED_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn respond_to_auth_challenge_user_not_found() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(USER_NOT_FOUND_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn respond_to_auth_challenge_too_many_requests_exception() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(TOO_MANY_REQUESTS_EXCEPTION_RESPONSE),
                        )
                    })
            }

            pub(crate) fn respond_to_auth_challenge_service_unavailable() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(503).unwrap(),
                            SdkBody::from(SERVICE_UNAVAILABLE_RESPONSE),
                        )
                    })
            }

            pub(crate) fn respond_to_auth_challenge_throttling_exception() -> Rule {
                mock!(Client::respond_to_auth_challenge)
                    .then_http_response(|| {
                        HttpResponse::new(
                            StatusCode::try_from(400).unwrap(),
                            SdkBody::from(THROTTLING_EXCEPTION_RESPONSE),
                        )
                    })
            }
        }
    }
}
